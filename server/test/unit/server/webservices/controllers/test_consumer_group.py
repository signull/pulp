#!/usr/bin/python
#
# Copyright (c) 2013 Red Hat, Inc.
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.

import mock

from .... import base
from pulp.devel import mock_plugins
from pulp.devel.unit.base import PulpWebservicesTests
from pulp.plugins.loader import api as plugin_api
from pulp.server.auth import authorization
from pulp.server.db.model.criteria import Criteria
from pulp.server.db.model.consumer import Consumer, ConsumerGroup, Bind
from pulp.server.db.model.repository import Repo, RepoDistributor
from pulp.server.exceptions import OperationPostponed
from pulp.server.managers import factory as managers
from pulp.server.webservices.controllers import consumer_groups

GROUP_ID = 'group_1'
CONSUMER_IDS = ('test_1', 'test_2', 'test_3')
REPO_ID = 'test-repo'
DISTRIBUTOR_ID = 'dist-1'
NOTIFY_AGENT = True
BINDING_CONFIG = {'b': 'b'}
DISTRIBUTOR_TYPE_ID = 'mock-distributor'


class ConsumerGroupAssociationTests(base.PulpWebserviceTests):
    def setUp(self):
        super(ConsumerGroupAssociationTests, self).setUp()
        self.manager = managers.consumer_group_manager()

    def clean(self):
        super(ConsumerGroupAssociationTests, self).clean()
        ConsumerGroup.get_collection().remove()

    @mock.patch.object(Criteria, 'from_client_input', return_value=Criteria())
    @mock.patch('pulp.server.managers.consumer.group.cud.ConsumerGroupManager.associate')
    def test_associate(self, mock_associate, mock_from_client):
        self.manager.create_consumer_group('cg1')

        post_data = {'criteria': {'filters': {'id': {'$in': ['consumer1']}}}}
        status, body = self.post('/v2/consumer_groups/cg1/actions/associate/', post_data)
        self.assertEqual(status, 200)

        self.assertEqual(mock_associate.call_count, 1)
        call_args = mock_associate.call_args[0]
        self.assertEqual(call_args[0], 'cg1')
        # verify that it created and used a Criteria instance
        self.assertEqual(call_args[1], mock_from_client.return_value)
        self.assertEqual(mock_from_client.call_args[0][0],
                         {'filters': {'id': {'$in': ['consumer1']}}})

    @mock.patch.object(Criteria, 'from_client_input', return_value=Criteria())
    @mock.patch('pulp.server.managers.consumer.group.cud.ConsumerGroupManager.unassociate')
    def test_unassociate(self, mock_unassociate, mock_from_client):
        self.manager.create_consumer_group('cg1')

        post_data = {'criteria': {'filters': {'id': {'$in': ['consumer1']}}}}
        status, body = self.post('/v2/consumer_groups/cg1/actions/unassociate/', post_data)
        self.assertEqual(status, 200)

        self.assertEqual(mock_unassociate.call_count, 1)
        call_args = mock_unassociate.call_args[0]
        self.assertEqual(call_args[0], 'cg1')
        # verify that it created and used a Criteria instance
        self.assertEqual(call_args[1], mock_from_client.return_value)
        self.assertEqual(mock_from_client.call_args[0][0],
                         {'filters': {'id': {'$in': ['consumer1']}}})
        

class ContentTest(PulpWebservicesTests):

    @mock.patch('pulp.server.webservices.controllers.consumer_groups.consumer_group.install_content')
    def test_install(self, mock_task):
        # Setup
        webservice = consumer_groups.ConsumerGroupContentAction()
        webservice.params = mock.Mock(return_value={'units': 'foo-unit',
                                                    'options': 'bar'})
        mock_task.return_value = 'baz'

        # Test
        self.assertRaises(OperationPostponed, webservice.install, 'consumer-foo')
        mock_task.assert_called_once_with('consumer-foo', 'foo-unit', 'bar')

    @mock.patch('pulp.server.webservices.controllers.consumer_groups.consumer_group.update_content')
    def test_update(self, mock_task):
        # Setup
        webservice = consumer_groups.ConsumerGroupContentAction()
        webservice.params = mock.Mock(return_value={'units': 'foo-unit',
                                                    'options': 'bar'})
        mock_task.return_value = 'baz'

        # Test
        self.assertRaises(OperationPostponed, webservice.update, 'consumer-foo')
        mock_task.assert_called_once_with('consumer-foo', 'foo-unit', 'bar')

    @mock.patch('pulp.server.webservices.controllers.consumer_groups.'
                'consumer_group.uninstall_content')
    def test_uninstall(self, mock_task):
        # Setup
        webservice = consumer_groups.ConsumerGroupContentAction()
        webservice.params = mock.Mock(return_value={'units': 'foo-unit',
                                                    'options': 'bar'})
        mock_task.return_value = 'baz'

        # Test
        self.assertRaises(OperationPostponed, webservice.uninstall, 'consumer-foo')
        mock_task.assert_called_once_with('consumer-foo', 'foo-unit', 'bar')


class BindTestNoWSGI(PulpWebservicesTests):
    """
    Tests that have been converted to no longer require the full web.py stack
    """

    @mock.patch('pulp.server.tasks.consumer_group.bind', autospec=True)
    def test_bind(self, mock_bind_task):
        bindings = consumer_groups.ConsumerGroupBindings()
        bindings.params = mock.Mock(return_value={'repo_id': 'foo-repo',
                                                  'distributor_id': 'bar-distributor',
                                                  'notify_agent': True})
        mock_bind_task.apply_async.return_value.id = 'foo'

        self.assertRaises(OperationPostponed, bindings.POST, 'consumer-group-id')
        mock_bind_task.apply_async.assert_called_once_with(('consumer-group-id',
                                                            'foo-repo',
                                                            'bar-distributor',
                                                            True, mock.ANY, mock.ANY))

        #validate the permissions
        self.validate_auth(authorization.CREATE)

    @mock.patch('pulp.server.tasks.consumer_group.bind', autospec=True)
    def test_bind_no_agent_notification(self, mock_bind_task):
        bindings = consumer_groups.ConsumerGroupBindings()
        bindings.params = mock.Mock(return_value={'repo_id': 'foo-repo',
                                                  'distributor_id': 'bar-distributor',
                                                  'notify_agent': False})
        mock_bind_task.apply_async.return_value.id = 'foo'

        self.assertRaises(OperationPostponed, bindings.POST, 'consumer-group-id')
        mock_bind_task.apply_async.assert_called_once_with(('consumer-group-id',
                                                            'foo-repo',
                                                            'bar-distributor',
                                                            False, mock.ANY, mock.ANY))

    @mock.patch('pulp.server.tasks.consumer_group.unbind', autospec=True)
    def test_unbind(self, mock_bind_task):
        binding = consumer_groups.ConsumerGroupBinding()
        mock_bind_task.apply_async.return_value.id = 'foo'

        self.assertRaises(OperationPostponed, binding.DELETE, 'consumer-group-id', 'repo-id',
                          'dist-id')
        mock_bind_task.apply_async.assert_called_once_with(('consumer-group-id',
                                                            'repo-id',
                                                            'dist-id', mock.ANY))

        #validate the permissions
        self.validate_auth(authorization.DELETE)


class BindTest(base.PulpWebserviceTests):

    def setUp(self):
        super(self.__class__, self).setUp()
        Consumer.get_collection().remove()
        ConsumerGroup.get_collection().remove()
        Repo.get_collection().remove()
        RepoDistributor.get_collection().remove()
        Bind.get_collection().remove()
        plugin_api._create_manager()
        mock_plugins.install()

    def tearDown(self):
        super(self.__class__, self).tearDown()
        Consumer.get_collection().remove()
        ConsumerGroup.get_collection().remove()
        Repo.get_collection().remove()
        RepoDistributor.get_collection().remove()
        Bind.get_collection().remove()
        mock_plugins.reset()

    def populate(self):
        manager = managers.consumer_manager()
        for consumer_id in CONSUMER_IDS:
            manager.register(consumer_id)
        manager = managers.consumer_group_manager()
        manager.create_consumer_group(GROUP_ID)
        for consumer_id in CONSUMER_IDS:
            criteria = Criteria(filters={'id': consumer_id}, fields=['id'])
            manager.associate(GROUP_ID, criteria)
        manager = managers.repo_manager()
        manager.create_repo(REPO_ID)
        manager = managers.repo_distributor_manager()
        manager.add_distributor(
            REPO_ID,
            DISTRIBUTOR_TYPE_ID,
            {},
            True,
            distributor_id=DISTRIBUTOR_ID)

    @mock.patch.object(base.PulpWebserviceTests, 'HEADERS', spec=dict)
    def test_bindings_get_auth(self, mock_headers):
        """
        Test that when the proper authentication information is missing, the server returns a 401 error
        when ConsumerGroupBindings.GET is called
        """
        path = '/v2/consumer_groups/%s/bindings/' % GROUP_ID
        call_status, call_body = self.get(path)
        self.assertEqual(401, call_status)

    @mock.patch.object(base.PulpWebserviceTests, 'HEADERS', spec=dict)
    def test_binding_get_auth(self, mock_headers):
        """
        Test that when the proper authentication information is missing, the server returns a 401 error
        when ConsumerGroupBinding.GET is called
        """
        path = '/v2/consumer_groups/%s/bindings/%s/%s/' % (GROUP_ID, REPO_ID, DISTRIBUTOR_ID)
        call_status, call_body = self.get(path)
        self.assertEqual(401, call_status)
