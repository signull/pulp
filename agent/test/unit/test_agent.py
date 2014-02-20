# -*- coding: utf-8 -*-
#
# Copyright © 2014 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

import os

from hashlib import sha256
from unittest import TestCase

from mock import patch, Mock

TEST_CN = 'test-cn'
TEST_CONFIG = {}
TEST_BUNDLE = """
-----BEGIN RSA PRIVATE KEY-----
KEY
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
CERTIFICATE
-----END CERTIFICATE-----
"""

TEST_ID_CERT_DIR = '/tmp/cert-dir'
TEST_ID_CERT_FILE = 'test-cert'

with patch('pulp.client.consumer.config.read_config'):
    from pulp.agent.gofer import pulpplugin


CERT_PATH = os.path.join(TEST_ID_CERT_DIR, TEST_ID_CERT_FILE)

class TestUtils(TestCase):

    @patch('pulp.common.bundle.Bundle.read', return_value=TEST_BUNDLE)
    def test_secret(self, fake_read):
        cfg = Mock()
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        # test
        secret = pulpplugin.secret()

        # validation
        # the secret is the sha256 of the certificate part of the bundle.

        h = sha256()
        lines = TEST_BUNDLE.split('\n')
        certificate = '\n'.join(lines[4:7])
        h.update(certificate)
        self.assertTrue(fake_read.called)
        self.assertEqual(h.hexdigest(), secret)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    def test_bundle(self, *unused):
        cfg = Mock()
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        # test
        bundle = pulpplugin.ConsumerX509Bundle()
        cn = bundle.cn()

        # validation
        self.assertEqual(bundle.path, CERT_PATH)
        self.assertEqual(cn, TEST_CN)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Bindings.__init__')
    @patch('pulp.agent.gofer.pulpplugin.PulpConnection')
    def test_pulp_bindings(self, mock_conn, mock_bindings, *unused):
        cfg = Mock()
        cfg.server = Mock()
        cfg.server.host = 'test-host'
        cfg.server.port = 433
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        # test
        bindings = pulpplugin.PulpBindings()

        # validation
        mock_conn.assert_called_with(cfg.server.host, int(cfg.server.port), cert_filename=CERT_PATH)
        mock_bindings.assert_called_with(bindings, mock_conn())


class TestConduit(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_consumer_id(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        # test
        conduit = pulpplugin.Conduit()

        # validation
        self.assertEqual(conduit.consumer_id, TEST_CN)

    @patch('pulp.agent.gofer.pulpplugin.pulp_conf', TEST_CONFIG)
    def test_get_consumer_config(self, *unused):
        conduit = pulpplugin.Conduit()
        conf = conduit.get_consumer_config()
        self.assertEqual(conf, TEST_CONFIG)

    @patch('gofer.agent.rmi.Context.current')
    def test_update_progress(self, mock_current):
        mock_context = Mock()
        mock_context.progress = Mock()
        mock_current.return_value = mock_context
        conduit = pulpplugin.Conduit()
        report = {'a': 1}

        # test
        conduit.update_progress(report)

        # validation
        mock_context.progress.report.assert_called_with()
        self.assertEqual(mock_context.progress.details, report)

    @patch('gofer.agent.rmi.Context.current')
    def test_cancelled(self, mock_current):
        mock_context = Mock()
        mock_context.cancelled = Mock(return_value=True)
        mock_current.return_value = mock_context
        conduit = pulpplugin.Conduit()

        # test
        cancelled = conduit.cancelled()

        # validation
        self.assertTrue(cancelled)
        self.assertTrue(mock_context.cancelled.called)

    @patch('gofer.agent.rmi.Context.current')
    def test_cancelled(self, mock_current):
        mock_context = Mock()
        mock_context.cancelled = Mock(return_value=False)
        mock_current.return_value = mock_context
        conduit = pulpplugin.Conduit()

        # test
        cancelled = conduit.cancelled()

        # validation
        self.assertFalse(cancelled)
        self.assertTrue(mock_context.cancelled.called)


class TestRegistrationMonitor(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.PathMonitor.add')
    def test_init(self, mock_add):
        cfg = Mock()
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        # test
        pulpplugin.RegistrationMonitor.init()

        # validation
        mock_add.assert_called_with(CERT_PATH, pulpplugin.RegistrationMonitor.changed)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_registered(self, mock_find, *unused):
        cfg = Mock()
        cfg.server = Mock()
        cfg.server.host = 'test-host'
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        cfg.messaging = Mock()
        cfg.messaging.host = None
        cfg.messaging.scheme = 'tcp'
        cfg.messaging.port = 5672
        cfg.messaging.cacert = 'test-ca'
        cfg.messaging.clientcert = None
        pulpplugin.pulp_conf.graph.return_value = cfg

        plugin = Mock()
        plugin_cfg = Mock()
        plugin_cfg.messaging = Mock()
        plugin.cfg = Mock(return_value=plugin_cfg)
        mock_find.return_value = plugin

        # test
        pulpplugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        expected_url = '%s://%s:%s' % (cfg.messaging.scheme, cfg.server.host, cfg.messaging.port)
        self.assertEqual(plugin_cfg.messaging.url, expected_url)
        self.assertEqual(plugin_cfg.messaging.cacert, cfg.messaging.cacert)
        self.assertEqual(plugin_cfg.messaging.clientcert, CERT_PATH)

        mock_find().setuuid.assert_called_with(TEST_CN)

    @patch('pulp.common.bundle.Bundle.cn', return_value=TEST_CN)
    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_different_broker_host(self, mock_find, *unused):
        cfg = Mock()
        cfg.server = Mock()
        cfg.server.host = 'test-host'
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        cfg.messaging = Mock()
        cfg.messaging.host = 'different-than-pulp-server'
        cfg.messaging.scheme = 'tcp'
        cfg.messaging.port = 5672
        cfg.messaging.cacert = 'test-ca'
        cfg.messaging.clientcert = None
        pulpplugin.pulp_conf.graph.return_value = cfg

        plugin = Mock()
        plugin_cfg = Mock()
        plugin_cfg.messaging = Mock()
        plugin.cfg = Mock(return_value=plugin_cfg)
        mock_find.return_value = plugin

        # test
        pulpplugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        expected_url = '%s://%s:%s' % (cfg.messaging.scheme, cfg.messaging.host, cfg.messaging.port)
        self.assertEqual(plugin_cfg.messaging.url, expected_url)
        self.assertEqual(plugin_cfg.messaging.cacert, cfg.messaging.cacert)
        self.assertEqual(plugin_cfg.messaging.clientcert, CERT_PATH)

        mock_find().setuuid.assert_called_with(TEST_CN)

    @patch('pulp.agent.gofer.pulpplugin.Plugin.find')
    def test_changed_unregistered(self, mock_find):
        cfg = Mock()
        cfg.server = Mock()
        cfg.server.host = 'test-host'
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        # test
        pulpplugin.RegistrationMonitor.changed(CERT_PATH)

        # validation
        mock_find().setuuid.assert_called_with(None)


class TestSynchronization(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_registered(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        # test
        registered = pulpplugin.Synchronization.registered()

        # validation
        self.assertTrue(registered)

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_not_registered(self, mock_bundle):
        mock_bundle().cn = Mock(return_value=None)

        # test
        registered = pulpplugin.Synchronization.registered()

        # validation
        self.assertFalse(registered)

    @patch('pulp.agent.gofer.pulpplugin.Synchronization.registered')
    @patch('pulp.agent.gofer.pulpplugin.Profile.send')
    def test_send_profile_when_registered(self, mock_send, mock_registered):
        mock_registered.return_value = True
        # test
        pulpplugin.Synchronization.profile()

        # validation
        mock_registered.assert_called_with()
        mock_send.assert_called_with()

    @patch('pulp.agent.gofer.pulpplugin.Synchronization.registered')
    @patch('pulp.agent.gofer.pulpplugin.Profile.send')
    def test_nosend_profile_when_not_registered(self, mock_send, mock_registered):
        mock_registered.return_value = False
        # test
        pulpplugin.Synchronization.profile()

        # validation
        mock_registered.assert_called_with()
        self.assertFalse(mock_send.called)


class TestConsumer(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    def test_unregistered(self, mock_bundle, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().clean.return_value = _report

        # test
        consumer = pulpplugin.Consumer()
        report = consumer.unregistered()

        # validation
        mock_bundle().delete.assert_called_with()
        mock_dispatcher().clean.assert_called_with(mock_conduit())
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_bind(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().bind.return_value = _report

        # test
        bindings = [{'A': 1}]
        options = {'B': 2}
        consumer = pulpplugin.Consumer()
        report = consumer.bind(bindings, options)

        # validation
        mock_dispatcher().bind.assert_called_with(mock_conduit(), bindings, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_unbind(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().unbind.return_value = _report

        # test
        bindings = [{'A': 1}]
        options = {'B': 2}
        consumer = pulpplugin.Consumer()
        report = consumer.unbind(bindings, options)

        # validation
        mock_dispatcher().unbind.assert_called_with(mock_conduit(), bindings, options)
        self.assertEqual(report, _report.dict())


class TestContent(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_install(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().install.return_value = _report

        # test
        units = [{'A': 1}]
        options = {'B': 2}
        content = pulpplugin.Content()
        report = content.install(units, options)

        # validation
        mock_dispatcher().install.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_update(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().update.return_value = _report

        # test
        units = [{'A': 10}]
        options = {'B': 20}
        content = pulpplugin.Content()
        report = content.update(units, options)

        # validation
        mock_dispatcher().update.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())

    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    def test_uninstall(self, mock_dispatcher, mock_conduit):
        _report = Mock()
        _report.dict = Mock(return_value={'report': 883938})
        mock_dispatcher().uninstall.return_value = _report

        # test
        units = [{'A': 100}]
        options = {'B': 200}
        content = pulpplugin.Content()
        report = content.uninstall(units, options)

        # validation
        mock_dispatcher().uninstall.assert_called_with(mock_conduit(), units, options)
        self.assertEqual(report, _report.dict())


class TestProfile(TestCase):

    @patch('pulp.agent.gofer.pulpplugin.ConsumerX509Bundle')
    @patch('pulp.agent.gofer.pulpplugin.Conduit')
    @patch('pulp.agent.gofer.pulpplugin.Dispatcher')
    @patch('pulp.agent.gofer.pulpplugin.PulpBindings')
    def test_send(self, mock_bindings, mock_dispatcher, mock_conduit, mock_bundle):
        mock_bundle().cn = Mock(return_value=TEST_CN)

        cfg = Mock()
        cfg.server = Mock()
        cfg.server.host = 'test-host'
        cfg.filesystem = Mock()
        cfg.filesystem.id_cert_dir = TEST_ID_CERT_DIR
        cfg.filesystem.id_cert_filename = TEST_ID_CERT_FILE
        pulpplugin.pulp_conf.graph.return_value = cfg

        _report = Mock()
        _report.details = {
            'AA': {'succeeded': False, 'details': 1234},
            'BB': {'succeeded': True, 'details': 5678}
        }
        _report.dict = Mock(return_value=_report.details)

        mock_dispatcher().profile.return_value = _report

        # test
        profile = pulpplugin.Profile()
        report = profile.send()

        # validation
        mock_dispatcher().profile.assert_called_with(mock_conduit())
        mock_bindings().profile.send.assert_called_once_with(TEST_CN, 'BB', 5678)