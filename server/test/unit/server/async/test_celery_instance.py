# -*- coding: utf-8 -*-
#
# Copyright © 2013 Red Hat, Inc.
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
This module contains tests for the pulp.server.async.celery_instance module.
"""
from datetime import timedelta
from functools import partial
import unittest

import mock

from pulp.server.async import celery_instance
from pulp.server.async.tasks import babysit
from pulp.server.config import config
from pulp.server.db.reaper import reap_expired_documents
from pulp.server.maintenance.monthly import monthly_maintenance


class TestCelerybeatSchedule(unittest.TestCase):
    """
    Assert that the CELERYBEAT_SCHEDULE structure has the expected tasks in it.
    """
    def test_num_tasks(self):
        """
        Assert that the expected number of beat tasks are in the CELERYBEAT_SCHEDULE. If you find
        youself adjusting this test because you added a new task to CELERYBEAT_SCHEDULE, please do
        add another unit test to this test class asserting that your new task is present with the
        correct information. Thanks!
        """
        # Please read the docblock to this test if you find yourself needing to adjust this
        # assertion.
        self.assertEqual(len(celery_instance.celery.conf['CELERYBEAT_SCHEDULE']), 3)

    def test_babysit(self):
        """
        Make sure the babysit Task is present and properly configured.
        """
        expected_babysit = {
            'task': babysit.name,
            'schedule': timedelta(seconds=60),
            'args': tuple(),
        }
        self.assertEqual(celery_instance.celery.conf['CELERYBEAT_SCHEDULE']['babysit'],
                         expected_babysit)

    def test_reap_expired_documents(self):
        """
        Make sure the reap_expired_documents Task is present and properly configured.
        """
        reap = celery_instance.celery.conf['CELERYBEAT_SCHEDULE']['reap_expired_documents']
        expected_reap = {
            'task': reap_expired_documents.name,
            'schedule': timedelta(days=(config.getfloat('data_reaping', 'reaper_interval'))),
            'args': tuple(),
        }
        self.assertEqual(reap, expected_reap)

    def test_monthly_maintenance(self):
        """
        Make sure the monthly maintenance Task is present and properly configured.
        """
        expected_monthly_maintenance = {
            'task': monthly_maintenance.name,
            'schedule': timedelta(days=30),
            'args': tuple(),
        }
        self.assertEqual(celery_instance.celery.conf['CELERYBEAT_SCHEDULE']['monthly_maintenance'],
                         expected_monthly_maintenance)

    def test_celery_conf_updated(self):
        """
        Make sure the Celery config was updated with our CELERYBEAT_SCHEDULE.
        """
        self.assertEqual(celery_instance.celery.conf['CELERYBEAT_SCHEDULE'],
                         celery_instance.CELERYBEAT_SCHEDULE)


def fake_get(config, section, key):
    """
    Fake version of the get() method from pulp's config object. This is useful
    so we can have concrete values to test for.
    """
    return config.get(key)


CONFIG = {
    'name': 'database_name',
    'seeds': 'host1:27017,host2:27017',
    'user': 'someguy',
    'password': 'letmein',
}


class TestMongoBackendConfig(unittest.TestCase):

    def test_celery_conf_updated(self):
        self.assertEqual(celery_instance.celery.conf['CELERY_RESULT_BACKEND'], 'mongodb')
        self.assertTrue(isinstance(celery_instance.celery.conf['CELERY_MONGODB_BACKEND_SETTINGS'], dict))

        conf = celery_instance.celery.conf['CELERY_MONGODB_BACKEND_SETTINGS']

        self.assertTrue(conf.get('host') is not None)
        self.assertTrue(conf.get('database') is not None)

    @mock.patch('pulp.server.async.celery_instance.config.has_option', new=lambda x, y: True)
    def test_create_config(self):
        custom_fake_get = partial(fake_get, CONFIG)
        with mock.patch('pulp.server.async.celery_instance.config.get', new=custom_fake_get):
            result = celery_instance.create_mongo_config()

            self.assertEqual(result['host'], 'host1')
            self.assertEqual(result['port'], '27017')
            self.assertEqual(result['database'], 'database_name')
            self.assertEqual(result['user'], 'someguy')
            self.assertEqual(result['password'], 'letmein')

    @mock.patch('pulp.server.async.celery_instance.config.has_option', new=lambda x, y: True)
    def test_create_config_one_seed(self):
        config = CONFIG.copy()
        config['seeds'] = config['seeds'].split(',')[0]
        custom_fake_get = partial(fake_get, config)
        with mock.patch('pulp.server.async.celery_instance.config.get', new=custom_fake_get):
            result = celery_instance.create_mongo_config()

            self.assertEqual(result['host'], 'host1')
            self.assertEqual(result['port'], '27017')

    @mock.patch('pulp.server.async.celery_instance.config.has_option', new=lambda x, y: True)
    def test_create_config_no_port(self):
        config = CONFIG.copy()
        config['seeds'] = 'host1'
        custom_fake_get = partial(fake_get, config)
        with mock.patch('pulp.server.async.celery_instance.config.get', new=custom_fake_get):
            result = celery_instance.create_mongo_config()

            self.assertEqual(result['host'], 'host1')
            self.assertTrue('port' not in result)

    @mock.patch('pulp.server.config.config.has_option',
                new=lambda x, y: False if y == 'password' else True)
    def test_no_password(self):
        custom_fake_get = partial(fake_get, CONFIG)
        with mock.patch('pulp.server.async.celery_instance.config.get', new=custom_fake_get):
            result = celery_instance.create_mongo_config()

            self.assertTrue('user' not in result)
            self.assertTrue('password' not in result)

    @mock.patch('pulp.server.config.config.has_option',
                new=lambda x, y: False if y == 'user' else True)
    def test_no_user(self):
        custom_fake_get = partial(fake_get, CONFIG)
        with mock.patch('pulp.server.async.celery_instance.config.get', new=custom_fake_get):
            result = celery_instance.create_mongo_config()

            self.assertTrue('user' not in result)
            self.assertTrue('password' not in result)
