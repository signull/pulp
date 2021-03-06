# -*- coding: utf-8 -*-
#
# Copyright © 2013 Red Hat, Inc.
#
#
# This software is licensed to you under the GNU General Public
# License as published by the Free Software Foundation; either version
# 2 of the License (GPLv2) or (at your option) any later version.
# There is NO WARRANTY for this software, express or implied,
# including the implied warranties of MERCHANTABILITY,
# NON-INFRINGEMENT, or FITNESS FOR A PARTICULAR PURPOSE. You should
# have received a copy of GPLv2 along with this software; if not, see
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
"""
This module contains tests for the pulp.server.async.task_status_manager module.
"""
import mock
import uuid

from ... import base

from pulp.common import dateutils
from pulp.server.async.task_status_manager import TaskStatusManager
from pulp.server.db.model.criteria import Criteria
from pulp.server.db.model.dispatch import TaskStatus
import pulp.server.exceptions as exceptions


class TaskStatusManagerTests(base.PulpServerTests):
    """
    Test the TaskStatusManager class.
    """
    def clean(self):
        super(TaskStatusManagerTests, self).clean()
        TaskStatus.get_collection().remove()

    def get_random_uuid(self):
        return str(uuid.uuid4())

    def test_create_task_status(self):
        """
        Tests that create_task_status() with valid data is successful.
        """
        task_id = self.get_random_uuid()
        queue = 'a_queue'
        tags = ['test-tag1', 'test-tag2']
        state = 'waiting'

        created = TaskStatusManager.create_task_status(task_id, queue, tags, state)

        task_statuses = list(TaskStatus.get_collection().find())
        self.assertEqual(1, len(task_statuses))

        task_status = task_statuses[0]
        self.assertEqual(task_id, task_status['task_id'])
        self.assertEqual(queue, task_status['queue'])
        self.assertEqual(tags, task_status['tags'])
        self.assertEqual(state, task_status['state'])

        self.assertEqual(task_id, created['task_id'])
        self.assertEqual(tags, created['tags'])
        self.assertEqual(state, created['state'])

    def test_create_task_status_defaults(self):
        """
        Tests create_task_status() with minimal information, to ensure that defaults are handled
        properly.
        """
        task_id = self.get_random_uuid()
        queue = 'a_queue'

        TaskStatusManager.create_task_status(task_id, queue)

        task_statuses = list(TaskStatus.get_collection().find())
        self.assertEqual(1, len(task_statuses))
        self.assertEqual(task_id, task_statuses[0]['task_id'])
        self.assertEqual(queue, task_statuses[0]['queue'])
        self.assertEqual([], task_statuses[0]['tags'])
        self.assertEqual(None, task_statuses[0]['state'])

    def test_create_task_status_invalid_task_id(self):
        """
        Test that calling create_task_status() with an invalid task id raises the correct error.
        """
        try:
            TaskStatusManager.create_task_status(None, 'some_queue')
            self.fail('Invalid ID did not raise an exception')
        except exceptions.InvalidValue, e:
            self.assertTrue(e.property_names[0], 'task_id')

    def test_create_task_status_duplicate_task_id(self):
        """
        Tests create_task_status() with a duplicate task id.
        """
        task_id = self.get_random_uuid()
        queue = 'a_queue'

        TaskStatusManager.create_task_status(task_id, queue)
        try:
            TaskStatusManager.create_task_status(task_id, queue)
            self.fail('Task status with a duplicate task id did not raise an exception')
        except exceptions.DuplicateResource, e:
            self.assertTrue(task_id in e)

    def test_create_task_status_invalid_attributes(self):
        """
        Tests that calling create_task_status() with invalid attributes
        results in an error
        """
        task_id = self.get_random_uuid()
        # queue is not allowed to be None
        queue = None
        tags = 'not a list'
        state = 1
        try:
            TaskStatusManager.create_task_status(task_id, queue, tags, state)
            self.fail('Invalid attributes did not cause create to raise an exception')
        except exceptions.InvalidValue, e:
            self.assertTrue('tags' in e.data_dict()['property_names'])
            self.assertTrue('state' in e.data_dict()['property_names'])
            self.assertTrue('queue' in e.data_dict()['property_names'])

    def test_delete_task_status(self):
        """
        Test delete_task_status() under normal circumstances.
        """
        task_id = self.get_random_uuid()
        TaskStatusManager.create_task_status(task_id, 'a_queue')

        TaskStatusManager.delete_task_status(task_id)

        task_statuses = list(TaskStatusManager.find_all())
        self.assertEqual(0, len(task_statuses))

    def test_delete_not_existing_task_status(self):
        """
        Tests that deleting a task status that doesn't exist raises the appropriate error.
        """
        task_id = self.get_random_uuid()
        try:
            TaskStatusManager.delete_task_status(task_id)
            self.fail('Exception expected')
        except exceptions.MissingResource, e:
            self.assertTrue(task_id == e.resources['resource_id'])

    def test_update_task_status(self):
        """
        Tests the successful operation of update_task_status().
        """
        task_id = self.get_random_uuid()
        queue = 'special_queue'
        tags = ['test-tag1', 'test-tag2']
        state = 'waiting'
        TaskStatusManager.create_task_status(task_id, queue, tags, state)
        delta = {'start_time': dateutils.now_utc_timestamp(),
                 'state': 'running',
                 'disregard': 'ignored',
                 'progress_report': {'report-id': 'my-progress'}}

        updated = TaskStatusManager.update_task_status(task_id, delta)

        task_status =  TaskStatusManager.find_by_task_id(task_id)
        self.assertEqual(task_status['start_time'], delta['start_time'])
        self.assertEqual(task_status['state'], delta['state'])
        self.assertEqual(task_status['progress_report'], delta['progress_report'])
        self.assertEqual(task_status['queue'], queue)
        self.assertEqual(updated['start_time'], delta['start_time'])
        self.assertEqual(updated['state'], delta['state'])
        self.assertEqual(updated['progress_report'], delta['progress_report'])
        self.assertTrue('disregard' not in updated)
        self.assertTrue('disregard' not in task_status)

    def test_update_missing_task_status(self):
        """
        Tests updating a task status that doesn't exist raises the appropriate exception.
        """
        task_id = self.get_random_uuid()
        try:
            TaskStatusManager.update_task_status(task_id, {})
            self.fail('Exception expected')
        except exceptions.MissingResource, e:
            self.assertTrue(task_id == e.resources['resource_id'])

    @mock.patch('pulp.server.db.connection.PulpCollection.query')
    def test_find_by_criteria(self, mock_query):
        criteria = Criteria()
        TaskStatusManager.find_by_criteria(criteria)
        mock_query.assert_called_once_with(criteria)
