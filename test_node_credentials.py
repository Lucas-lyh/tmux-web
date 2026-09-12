"""Enrollment cache and encrypted handoff tests using synthetic keys and /tmp."""

import asyncio
import contextlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import node


IDENTIFIER = "1" * 32
JOIN = "twj." + IDENTIFIER + "." + "2" * 64
PERMANENT = "twn." + IDENTIFIER + "." + "3" * 64
REPLACEMENT = "twn." + IDENTIFIER + "." + "4" * 64
ENDPOINT = "ws://localhost:59999/ws-node"


class NodeCredentialTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tmux-credential-test-")
        self.directory = Path(self.temp.name) / "state"
        self.directory_patch = mock.patch.object(node, "node_credential_directory", return_value=str(self.directory))
        self.directory_patch.start()

    async def asyncTearDown(self):
        self.directory_patch.stop()
        self.temp.cleanup()

    def agent(self, token=JOIN, endpoint=ENDPOINT, name="test-node"):
        return node.Agent(endpoint, token, name)

    def cache_path(self, endpoint=ENDPOINT, name="test-node"):
        return self.directory / node._credential_filename(endpoint, name, IDENTIFIER)

    async def test_legacy_token_does_not_touch_state_or_add_key_selector(self):
        with mock.patch.object(node, "node_credential_directory", side_effect=AssertionError("legacy token must not use state")):
            agent = self.agent("legacy-manual-key")
            self.assertEqual(agent.node_url, ENDPOINT + "?v=2")
            agent.ws = SimpleNamespace(send_json=mock.AsyncMock())
            with self.assertRaises(node.CredentialError):
                await agent.handle({"type": "hello-ok", "credential": PERMANENT})
            agent.ws.send_json.assert_not_awaited()

    async def test_first_enrollment_adds_only_public_id_without_creating_cache(self):
        agent = self.agent()
        self.assertEqual(agent.token, JOIN)
        self.assertEqual(agent.node_url, ENDPOINT + "?v=2&key=twj." + IDENTIFIER)
        self.assertNotIn(JOIN, agent.node_url)
        self.assertFalse(self.directory.exists())

    async def test_save_and_token_switch_precede_encrypted_ack(self):
        agent = self.agent()
        original_argv = list(sys.argv)

        async def acknowledge(message):
            self.assertEqual(message, {"type": "credential-ack"})
            self.assertEqual(self.cache_path().read_text().strip(), PERMANENT)
            self.assertEqual(self.cache_path().stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(agent.token, PERMANENT)
            self.assertEqual(agent.node_url, ENDPOINT + "?v=2&key=twn." + IDENTIFIER)
            self.assertFalse(agent._hello_received)

        agent.ws = SimpleNamespace(send_json=mock.AsyncMock(side_effect=acknowledge))
        with mock.patch("builtins.print") as output:
            await agent.handle({"type": "hello-ok", "credential": PERMANENT})
        self.assertTrue(agent._hello_received)
        agent.ws.send_json.assert_awaited_once()
        self.assertEqual(sys.argv, original_argv)
        self.assertNotIn(JOIN, str(output.call_args_list))
        self.assertNotIn(PERMANENT, str(output.call_args_list))

    async def test_old_bootstrap_command_reuses_same_id_cached_permanent_key(self):
        node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        resumed = self.agent(JOIN)
        self.assertEqual(resumed.token, PERMANENT)
        self.assertEqual(resumed.node_url, ENDPOINT + "?v=2&key=twn." + IDENTIFIER)
        self.assertEqual(self.agent(JOIN, name="other-node").token, JOIN)
        self.assertEqual(self.agent(JOIN, endpoint="ws://localhost:60000/ws-node").token, JOIN)
        self.assertEqual(self.agent(JOIN, endpoint="ws://localhost:59999/other-node").token, JOIN)

    async def test_reconnect_reloads_cache_completed_by_another_bootstrap_process(self):
        agent = self.agent()
        node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        with mock.patch.object(node.Ws, "connect", new_callable=mock.AsyncMock,
                               side_effect=asyncio.CancelledError) as connect, mock.patch("builtins.print"):
            with self.assertRaises(asyncio.CancelledError):
                await agent.run()
        self.assertEqual(agent.token, PERMANENT)
        connect.assert_awaited_once_with(ENDPOINT + "?v=2&key=twn." + IDENTIFIER)

    async def test_endpoint_normalization_keeps_equivalent_address_cache(self):
        node.save_node_credential("ws://LOCALHOST:80/ws-node", "test-node", PERMANENT)
        self.assertEqual(self.agent(JOIN, endpoint="ws://localhost/ws-node").token, PERMANENT)

    async def test_id_mismatch_and_invalid_replacements_never_save_or_ack(self):
        agent = self.agent()
        agent.ws = SimpleNamespace(send_json=mock.AsyncMock())
        for replacement in (JOIN, 123, None, {}, "twn." + "9" * 32 + "." + "3" * 64):
            with self.subTest(kind=type(replacement).__name__):
                with mock.patch.object(node, "save_node_credential") as save:
                    with self.assertRaises(node.CredentialError):
                        await agent.handle({"type": "hello-ok", "credential": replacement})
                    save.assert_not_called()
        self.assertEqual(agent.token, JOIN)
        agent.ws.send_json.assert_not_awaited()
        self.assertFalse(self.directory.exists())

    async def test_enrollment_requires_permanent_credential_but_old_tokens_do_not(self):
        with self.assertRaises(node.CredentialError):
            await self.agent().handle({"type": "hello-ok"})
        with mock.patch("builtins.print"):
            for token in (PERMANENT, "legacy-manual-key"):
                agent = self.agent(token)
                await agent.handle({"type": "hello-ok"})
                self.assertTrue(agent._hello_received)

    async def test_failed_persistence_sends_no_ack_and_keeps_current_key(self):
        agent = self.agent()
        agent.ws = SimpleNamespace(send_json=mock.AsyncMock())
        with mock.patch.object(node.os, "replace", side_effect=OSError("simulated persistence error")):
            with self.assertRaises(node.CredentialError) as failure:
                await agent.handle({"type": "hello-ok", "credential": PERMANENT})
        self.assertNotIn(PERMANENT, str(failure.exception))
        self.assertEqual(agent.token, JOIN)
        self.assertFalse(agent._hello_received)
        self.assertEqual(list(self.directory.iterdir()), [])
        agent.ws.send_json.assert_not_awaited()

    async def test_fsync_failure_cannot_replace_existing_cache_with_partial_file(self):
        node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        with mock.patch.object(node.os, "fsync", side_effect=OSError("simulated fsync failure")):
            with self.assertRaises(node.CredentialError):
                node.save_node_credential(ENDPOINT, "test-node", REPLACEMENT)
        self.assertEqual(node.load_node_credential(ENDPOINT, "test-node", JOIN), PERMANENT)
        self.assertEqual(list(self.directory.iterdir()), [self.cache_path()])

    async def test_ack_failure_keeps_permanent_key_for_reconnect_and_restart(self):
        agent = self.agent()
        agent.ws = SimpleNamespace(send_json=mock.AsyncMock(side_effect=ConnectionError("simulated lost ack")))
        with self.assertRaises(ConnectionError):
            await agent.handle({"type": "hello-ok", "credential": PERMANENT})
        self.assertFalse(agent._hello_received)
        self.assertEqual(agent.token, PERMANENT)
        self.assertEqual(self.agent(JOIN).token, PERMANENT)

    async def test_cancelled_ack_also_keeps_durable_permanent_key(self):
        agent = self.agent()
        awaiting_ack = asyncio.Event()

        async def acknowledge(message):
            awaiting_ack.set()
            await asyncio.Event().wait()

        agent.ws = SimpleNamespace(send_json=acknowledge)
        task = asyncio.create_task(agent.handle({"type": "hello-ok", "credential": PERMANENT}))
        await awaiting_ack.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(agent.token, PERMANENT)
        self.assertEqual(self.agent(JOIN).token, PERMANENT)

    async def test_invalid_cache_is_rejected_without_falling_back_to_spent_join_key(self):
        self.directory.mkdir(mode=0o700)
        for content in (JOIN, "invalid", "twn." + "9" * 32 + "." + "3" * 64, "x" * 300):
            self.cache_path().write_text(content)
            self.cache_path().chmod(0o600)
            with self.subTest(length=len(content)), self.assertRaises(node.CredentialError):
                self.agent()

    async def test_cache_symlink_and_insecure_permissions_are_rejected(self):
        node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        self.cache_path().chmod(0o644)
        with self.assertRaises(node.CredentialError):
            self.agent()
        self.cache_path().unlink()
        outside = Path(self.temp.name) / "outside"
        outside.write_text(PERMANENT)
        outside.chmod(0o600)
        self.cache_path().symlink_to(outside)
        with self.assertRaises(node.CredentialError):
            self.agent()
        with self.assertRaises(node.CredentialError):
            node.save_node_credential(ENDPOINT, "test-node", REPLACEMENT)
        self.assertEqual(outside.read_text(), PERMANENT)

    async def test_directory_symlink_and_wrong_owner_are_rejected(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir(mode=0o700)
        self.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(node.CredentialError):
            self.agent()
        with self.assertRaises(node.CredentialError):
            node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        self.directory.unlink()
        self.directory.mkdir(mode=0o700)
        with mock.patch.object(node.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises(node.CredentialError):
                self.agent()

    async def test_cache_permissions_are_exact_even_under_restrictive_umask(self):
        self.directory.mkdir(mode=0o700)
        previous = os.umask(0o777)
        try:
            node.save_node_credential(ENDPOINT, "test-node", PERMANENT)
        finally:
            os.umask(previous)
        self.assertEqual(self.cache_path().stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)

    async def test_only_named_credentials_advertise_handoff_capability(self):
        for token in (JOIN, PERMANENT, "legacy-manual-key"):
            agent = self.agent(token)
            sent = []
            ready = asyncio.Event()

            async def send_json(message):
                sent.append(message)
                ready.set()

            async def recv():
                await asyncio.Event().wait()

            agent.ws = SimpleNamespace(send_json=send_json, recv=recv)
            task = asyncio.create_task(agent.serve())
            await ready.wait()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            self.assertEqual("credential-v1" in sent[0]["capabilities"], token != "legacy-manual-key")


if __name__ == "__main__":
    unittest.main()
