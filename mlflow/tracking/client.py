"""
Internal package providing a Python CRUD interface to MLflow experiments and runs.
This is a lower level API than the :py:mod:`mlflow.tracking.fluent` module, and is
exposed in the :py:mod:`mlflow.tracking` module.
"""

import time
import os
from six import iteritems

from mlflow.store import SEARCH_MAX_RESULTS_DEFAULT
from mlflow.tracking import utils
from mlflow.utils.validation import _validate_param_name, _validate_tag_name, _validate_run_id, \
    _validate_experiment_artifact_location, _validate_experiment_name, _validate_metric
from mlflow.entities import Param, Metric, RunStatus, RunTag, ViewType, ExperimentTag
from mlflow.store.artifact_repository_registry import get_artifact_repository
from mlflow.utils.mlflow_tags import MLFLOW_USER
from mlflow.tracking import ranger

class MlflowClient(object):
    """
    Client of an MLflow Tracking Server that creates and manages experiments and runs.
    """

    def __init__(self, tracking_uri=None, user=None):
        """
        :param tracking_uri: Address of local or remote tracking server. If not provided, defaults
                             to the service set by ``mlflow.tracking.set_tracking_uri``. See
                             `Where Runs Get Recorded <../tracking.html#where-runs-get-recorded>`_
                             for more info.
        """
        self.tracking_uri = tracking_uri or utils.get_tracking_uri()
        self.user = user or os.environ.get('MLFLOW_RANGER_USER', 'mlflow')
        os.environ['MLFLOW_RANGER_USER'] = self.user
        self.store = utils._get_store(self.tracking_uri)

    def set_user(self, user):
        self.user = user
        os.environ['MLFLOW_RANGER_USER'] = user

    def get_user(self):
        self.user = os.environ.get('MLFLOW_RANGER_USER', self.user)
        return self.user

    def ranger_can_authorize_experiment_id(self, experiment_id, role='select'):
        rangerAccess = ranger.MLflowRangerAccess(user=self.get_user())
        rangerAccess.sync(role=role) # Place to optimize
        return rangerAccess.canAccessExperiment(experiment_id=experiment_id)

    def ranger_can_authorize_create_experiment(self):
        rangerAccess = ranger.MLflowRangerAccess(user=self.get_user())
        rangerAccess.sync(role=role) # Place to optimize
        return rangerAccess.canCreateExperiment()

    def get_run(self, run_id):
        """
        Fetch the run from backend store. The resulting :py:class:`Run <mlflow.entities.Run>`
        contains a collection of run metadata -- :py:class:`RunInfo <mlflow.entities.RunInfo>`,
        as well as a collection of run parameters, tags, and metrics --
        :py:class:`RunData <mlflow.entities.RunData>`. In the case where multiple metrics with the
        same key are logged for the run, the :py:class:`RunData <mlflow.entities.RunData>` contains
        the most recently logged value at the largest step for each metric.

        :param run_id: Unique identifier for the run.

        :return: A single :py:class:`mlflow.entities.Run` object, if the run exists. Otherwise,
                 raises an exception.
        """
        _validate_run_id(run_id)
        return self.store.get_run(run_id)

    def get_metric_history(self, run_id, key):
        """
        Return a list of metric objects corresponding to all values logged for a given metric.

        :param run_id: Unique identifier for run
        :param key: Metric name within the run

        :return: A list of :py:class:`mlflow.entities.Metric` entities if logged, else empty list
        """
        return self.store.get_metric_history(run_id=run_id, metric_key=key)

    def create_run(self, experiment_id, start_time=None, tags=None):
        """
        Create a :py:class:`mlflow.entities.Run` object that can be associated with
        metrics, parameters, artifacts, etc.
        Unlike :py:func:`mlflow.projects.run`, creates objects but does not run code.
        Unlike :py:func:`mlflow.start_run`, does not change the "active run" used by
        :py:func:`mlflow.log_param`.

        :param experiment_id: The ID of then experiment to create a run in.
        :param start_time: If not provided, use the current timestamp.
        :param tags: A dictionary of key-value pairs that are converted into
                     :py:class:`mlflow.entities.RunTag` objects.
        :return: :py:class:`mlflow.entities.Run` that was created.
        """

        if not self.ranger_can_authorize_experiment_id(experiment_id, 'write'):
            print("Access denied.")
            raise

        tags = tags if tags else {}

        # Extract user from tags
        # This logic is temporary; the user_id attribute of runs is deprecated and will be removed
        # in a later release.
        user_id = tags.get(MLFLOW_USER, "unknown")

        return self.store.create_run(
            experiment_id=experiment_id,
            user_id=user_id,
            start_time=start_time or int(time.time() * 1000),
            tags=[RunTag(key, value) for (key, value) in iteritems(tags)]
        )

    def list_run_infos(self, experiment_id, run_view_type=ViewType.ACTIVE_ONLY):
        """:return: List of :py:class:`mlflow.entities.RunInfo`"""

        if not self.ranger_can_authorize_experiment_id(experiment_id):
            print("Access denied.")
            raise

        return self.store.list_run_infos(experiment_id, run_view_type)

    def list_experiments(self, view_type=None):
        """
        :return: List of :py:class:`mlflow.entities.Experiment`
        """
        final_view_type = ViewType.ACTIVE_ONLY if view_type is None else view_type
        experiments = self.store.list_experiments(view_type=final_view_type)
        experiments = [exp for exp in experiments if self.ranger_can_authorize_experiment_id(exp.experiment_id)]
        return experiments


    def get_experiment(self, experiment_id):
        """
        :param experiment_id: The experiment ID returned from ``create_experiment``.
        :return: :py:class:`mlflow.entities.Experiment`
        """
        if not self.ranger_can_authorize_experiment_id(experiment_id):
            print("Access denied.")
            raise

        return self.store.get_experiment(experiment_id)

    def get_experiment_by_name(self, name):
        """
        :param name: The experiment name.
        :return: :py:class:`mlflow.entities.Experiment`
        """
        experiment = self.store.get_experiment_by_name(name)
        if not self.ranger_can_authorize_experiment_id(experiment.experiment_id):
            print("Access denied.")
            raise
        return experiment

    def create_experiment(self, name, artifact_location=None):
        """Create an experiment.

        :param name: The experiment name. Must be unique.
        :param artifact_location: The location to store run artifacts.
                                  If not provided, the server picks an appropriate default.
        :return: Integer ID of the created experiment.
        """
        if not self.ranger_can_authorize_create_experiment():
            print("Access denied.")
            raise
        _validate_experiment_name(name)
        _validate_experiment_artifact_location(artifact_location)
        return self.store.create_experiment(
            name=name,
            artifact_location=artifact_location,
        )

    def delete_experiment(self, experiment_id):
        """
        Delete an experiment from the backend store.

        :param experiment_id: The experiment ID returned from ``create_experiment``.
        """
        if not self.ranger_can_authorize_experiment_id(experiment_id, 'drop'):
            print("Access denied.")
            raise
        self.store.delete_experiment(experiment_id)

    def restore_experiment(self, experiment_id):
        """
        Restore a deleted experiment unless permanently deleted.

        :param experiment_id: The experiment ID returned from ``create_experiment``.
        """
        if not self.ranger_can_authorize_experiment_id(experiment_id, 'create'):
            print("Access denied.")
            raise
        self.store.restore_experiment(experiment_id)

    def rename_experiment(self, experiment_id, new_name):
        """
        Update an experiment's name. The new name must be unique.

        :param experiment_id: The experiment ID returned from ``create_experiment``.
        """
        if not self.ranger_can_authorize_experiment_id(experiment_id, 'update'):
            print("Access denied.")
            raise
        self.store.rename_experiment(experiment_id, new_name)

    def log_metric(self, run_id, key, value, timestamp=None, step=None):
        """
        Log a metric against the run ID.

        :param run_id: The run id to which the metric should be logged.
        :param key: Metric name.
        :param value: Metric value (float). Note that some special values such
                      as +/- Infinity may be replaced by other values depending on the store. For
                      example, the SQLAlchemy store replaces +/- Inf with max / min float values.
        :param timestamp: Time when this metric was calculated. Defaults to the current system time.
        :param step: Training step (iteration) at which was the metric calculated. Defaults to 0.
        """
        timestamp = timestamp if timestamp is not None else int(time.time())
        step = step if step is not None else 0
        _validate_metric(key, value, timestamp, step)
        metric = Metric(key, value, timestamp, step)
        self.store.log_metric(run_id, metric)

    def log_param(self, run_id, key, value):
        """
        Log a parameter against the run ID. Value is converted to a string.
        """
        _validate_param_name(key)
        param = Param(key, str(value))
        self.store.log_param(run_id, param)

    def set_experiment_tag(self, experiment_id, key, value):
        """
        Set a tag on the experiment with the specified ID. Value is converted to a string.
        :param experiment_id: String ID of the experiment.
        :param key: Name of the tag.
        :param value: Tag value (converted to a string).
        """
        if not self.ranger_can_authorize_experiment_id(experiment_id, 'update'):
            print("Access denied.")
            raise
        _validate_tag_name(key)
        tag = ExperimentTag(key, str(value))
        self.store.set_experiment_tag(experiment_id, tag)

    def set_tag(self, run_id, key, value):
        """
        Set a tag on the run with the specified ID. Value is converted to a string.
        :param run_id: String ID of the run.
        :param key: Name of the tag.
        :param value: Tag value (converted to a string)
        """
        _validate_tag_name(key)
        tag = RunTag(key, str(value))
        self.store.set_tag(run_id, tag)

    def delete_tag(self, run_id, key):
        """
        Delete a tag from a run. This is irreversible.

        :param run_id: String ID of the run
        :param key: Name of the tag
        """
        self.store.delete_tag(run_id, key)

    def log_batch(self, run_id, metrics=(), params=(), tags=()):
        """
        Log multiple metrics, params, and/or tags.

        :param run_id: String ID of the run
        :param metrics: If provided, List of Metric(key, value, timestamp) instances.
        :param params: If provided, List of Param(key, value) instances.
        :param tags: If provided, List of RunTag(key, value) instances.

        Raises an MlflowException if any errors occur.
        :return: None
        """
        if len(metrics) == 0 and len(params) == 0 and len(tags) == 0:
            return
        for metric in metrics:
            _validate_metric(metric.key, metric.value, metric.timestamp, metric.step)
        for param in params:
            _validate_param_name(param.key)
        for tag in tags:
            _validate_tag_name(tag.key)
        self.store.log_batch(run_id=run_id, metrics=metrics, params=params, tags=tags)

    def log_artifact(self, run_id, local_path, artifact_path=None):
        """
        Write a local file or directory to the remote ``artifact_uri``.

        :param local_path: Path to the file or directory to write.
        :param artifact_path: If provided, the directory in ``artifact_uri`` to write to.
        """
        run = self.get_run(run_id)
        artifact_repo = get_artifact_repository(run.info.artifact_uri)
        if os.path.isdir(local_path):
            dir_name = os.path.basename(os.path.normpath(local_path))
            path_name = os.path.join(artifact_path, dir_name) \
                if artifact_path is not None else dir_name
            artifact_repo.log_artifacts(local_path, path_name)
        else:
            artifact_repo.log_artifact(local_path, artifact_path)

    def log_artifacts(self, run_id, local_dir, artifact_path=None):
        """
        Write a directory of files to the remote ``artifact_uri``.

        :param local_dir: Path to the directory of files to write.
        :param artifact_path: If provided, the directory in ``artifact_uri`` to write to.
        """
        run = self.get_run(run_id)
        artifact_repo = get_artifact_repository(run.info.artifact_uri)
        artifact_repo.log_artifacts(local_dir, artifact_path)

    def list_artifacts(self, run_id, path=None):
        """
        List the artifacts for a run.

        :param run_id: The run to list artifacts from.
        :param path: The run's relative artifact path to list from. By default it is set to None
                     or the root artifact path.
        :return: List of :py:class:`mlflow.entities.FileInfo`
        """
        run = self.get_run(run_id)
        artifact_root = run.info.artifact_uri
        artifact_repo = get_artifact_repository(artifact_root)
        return artifact_repo.list_artifacts(path)

    def download_artifacts(self, run_id, path, dst_path=None):
        """
        Download an artifact file or directory from a run to a local directory if applicable,
        and return a local path for it.

        :param run_id: The run to download artifacts from.
        :param path: Relative source path to the desired artifact.
        :param dst_path: Absolute path of the local filesystem destination directory to which to
                         download the specified artifacts. This directory must already exist.
                         If unspecified, the artifacts will either be downloaded to a new
                         uniquely-named directory on the local filesystem or will be returned
                         directly in the case of the LocalArtifactRepository.
        :return: Local path of desired artifact.
        """
        run = self.get_run(run_id)
        artifact_root = run.info.artifact_uri
        artifact_repo = get_artifact_repository(artifact_root)
        return artifact_repo.download_artifacts(path, dst_path)

    def set_terminated(self, run_id, status=None, end_time=None):
        """Set a run's status to terminated.

        :param status: A string value of :py:class:`mlflow.entities.RunStatus`.
                       Defaults to "FINISHED".
        :param end_time: If not provided, defaults to the current time."""
        end_time = end_time if end_time else int(time.time() * 1000)
        status = status if status else RunStatus.to_string(RunStatus.FINISHED)
        self.store.update_run_info(run_id, run_status=RunStatus.from_string(status),
                                   end_time=end_time)

    def delete_run(self, run_id):
        """
        Deletes a run with the given ID.
        """
        self.store.delete_run(run_id)

    def restore_run(self, run_id):
        """
        Restores a deleted run with the given ID.
        """
        self.store.restore_run(run_id)

    def search_runs(self, experiment_ids, filter_string="", run_view_type=ViewType.ACTIVE_ONLY,
                    max_results=SEARCH_MAX_RESULTS_DEFAULT, order_by=None, page_token=None):
        """
        Search experiments that fit the search criteria.

        :param experiment_ids: List of experiment IDs, or a single int or string id.
        :param filter_string: Filter query string, defaults to searching all runs.
        :param run_view_type: one of enum values ACTIVE_ONLY, DELETED_ONLY, or ALL runs
                              defined in :py:class:`mlflow.entities.ViewType`.
        :param max_results: Maximum number of runs desired.
        :param order_by: List of columns to order by (e.g., "metrics.rmse"). The default
                         ordering is to sort by start_time DESC, then run_id.
        :param page_token: Token specifying the next page of results. It should be obtained from
            a ``search_runs`` call.

        :return: A list of :py:class:`mlflow.entities.Run` objects that satisfy the search
            expressions. If the underlying tracking store supports pagination, the token for
            the next page may be obtained via the ``token`` attribute of the returned object.
        """
        if isinstance(experiment_ids, int) or isinstance(experiment_ids, str):
            experiment_ids = [experiment_ids]
        for experiment_id in experiment_ids:
            if not self.ranger_can_authorize_experiment_id(experiment_id, 'select'):
                print("Access denied.")
                raise
        return self.store.search_runs(experiment_ids=experiment_ids, filter_string=filter_string,
                                      run_view_type=run_view_type, max_results=max_results,
                                      order_by=order_by, page_token=page_token)
