import socket
import os
import requests
from requests.auth import HTTPBasicAuth
import json
import itertools
import sqlparse
import re
from hashlib import sha256

HOSTNAME = socket.gethostname()
IPADDR = socket.gethostbyname(HOSTNAME)
DATA_MASK_POLICY_ITEMS = 'dataMaskPolicyItems'
DATA_MASK_INFO = 'dataMaskInfo'
DATA_MASK_TYPE = 'dataMaskType'
ROW_FILTER_POLICY_ITEMS = 'rowFilterPolicyItems'
ROW_FILTER_INFO = 'rowFilterInfo'
FILTER_EXPRESSION = 'filterExpr'
POLICY_ITEMS = 'policyItems'
DENY_POLICY_ITEMS = 'denyPolicyItems'
ACCESSES = 'accesses'
RESOURCES = 'resources'
COLUMN = 'column'
TABLE = 'table'
VALUES = 'values'
VALUE_EXPRESSION = 'valueExpr'
TYPE = 'type'
IS_ALLOWED = 'isAllowed'
DEBUG = False #False

class MLflowRangerAccess:
    def __init__(self, user):
        self.user = user
        self.acceptExperimentIds = set([])
        self.acceptRunIds = set([])
        self.denyExperimentIds = set([])
        self.denyRunIds = set([])
        self.acceptAllExperiments = False
        self.denyAllExperiments = False
        self.canCreate = False


    def sync(self,role='select', url='http://ranger-admin.kubeflow.svc.cluster.local:6080/service/public/v2/api/service/primary_hive/policy'):
        policies = get_ranger_policies_for(self.user, url=url, admin_user='admin', admin_pass='Ranger123', database='mlflow')
        for policy in policies:
            if DEBUG:
                print('Found policy: ', policy)
            if POLICY_ITEMS in policy:
                filter_policies = policy[POLICY_ITEMS]
                for filter_policy in filter_policies:
                    if DEBUG:
                        print('Found filter policy: ', filter_policy)
                    if ACCESSES in filter_policy:
                        accesses = filter_policy[ACCESSES]
                        if TABLE in policy[RESOURCES]:
                            experiments = policy[RESOURCES][TABLE][VALUES]
                            runs = policy[RESOURCES][COLUMN][VALUES]
                            for access in accesses:
                                if (access[TYPE] == role or access[TYPE]=='all') and access[IS_ALLOWED]:
                                    for experiment in experiments:
                                        if experiment is not None and experiment != '*':
                                            if DEBUG:
                                                print('Accepting experiment: ', experiment)
                                            self.acceptExperimentIds.add(experiment)
                                        elif experiment is not None and experiment == '*':
                                            self.acceptAllExperiments = True
                                if (access[TYPE] == 'create' or access[TYPE]=='all') and access[IS_ALLOWED]:
                                    self.canCreate = True
                                    if DEBUG:
                                        print('Can create experiments!')


            if DENY_POLICY_ITEMS in policy:
                filter_policies = policy[DENY_POLICY_ITEMS]
                for filter_policy in filter_policies:
                    if DEBUG:
                        print('Found deny filter policy: ', filter_policy)
                    if ACCESSES in filter_policy:
                        accesses = filter_policy[ACCESSES]
                        if TABLE in policy[RESOURCES]:
                            experiments = policy[RESOURCES][TABLE][VALUES]
                            runs = policy[RESOURCES][COLUMN][VALUES]
                            for access in accesses:
                                if access[TYPE] == role and access[IS_ALLOWED]:
                                    for experiment in experiments:
                                        if experiment is not None and experiment != '*':
                                            if DEBUG:
                                                print('Denying experiment: ', experiment)
                                            if experiment in self.acceptExperimentIds:
                                                self.acceptExperimentIds.remove(experiment)
                                            self.denyExperimentIds.add(experiment)
                                        elif experiment is not None and experiment == '*':
                                            self.denyAllExperiments = True

    def canAccessExperiment(self, experiment_id):
        if self.acceptAllExperiments:
            return experiment_id not in self.denyExperimentIds
        if self.denyAllExperiments:
            return experiment_id in self.acceptExperimentIds
        return experiment_id in self.acceptExperimentIds

    def canAccessRun(self, run_id):
        return run_id in self.acceptRunIds

    def canCreateExperiment(self):
        return self.canCreate


def get_ranger_policies_for(user, url, admin_user, admin_pass, database='mlflow', experiment_ids=[None], run_ids=[None]):
    all_policies = []
    for experiment_id in experiment_ids:
        for run_id in run_ids:
            params = {'user': user, 'isEnabled': 'true'}
            if database is not None:
                params['resource:database'] = database
            if experiment_id is not None:
                params['resource:table'] = experiment_id
            if run_id is not None:
                params['resource:column'] = run_id
            res = requests.get(url, params=params, auth=HTTPBasicAuth(admin_user, admin_pass))
            if DEBUG:
                text = res.text
                print('TEXT:', text)
                policies = json.loads(text)
            else:
                policies = res.json()
            [all_policies.append(policy) for policy in policies]
    return all_policies
