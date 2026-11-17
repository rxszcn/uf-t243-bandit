#    Copyright 2016 IBM Corp.
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from unittest import mock

import fixtures
import testtools

from bandit.cli import main as bandit
from bandit.core import extension_loader as ext_loader
from bandit.core import utils

bandit_config_content = """
include:
    - '*.py'
    - '*.pyw'

profiles:
    test:
        include:
            - start_process_with_a_shell

shell_injection:
    subprocess:

    shell:
        - os.system
"""

bandit_baseline_content = """{
    "results": [
        {
            "code": "some test code",
            "filename": "test_example.py",
            "issue_severity": "low",
            "issue_confidence": "low",
            "issue_text": "test_issue",
            "test_name": "some_test",
            "test_id": "x",
            "line_number": "n",
            "line_range": "n-m"
        }
    ]
}
"""


class BanditCLIMainLoggerTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.logger = logging.getLogger()
        self.original_logger_handlers = self.logger.handlers
        self.original_logger_level = self.logger.level
        self.logger.handlers = []

    def tearDown(self):
        super().tearDown()
        self.logger.handlers = self.original_logger_handlers
        self.logger.level = self.original_logger_level

    def test_init_logger(self):
        # Test that a logger was properly initialized
        bandit._init_logger()

        self.assertIsNotNone(self.logger)
        self.assertNotEqual(self.logger.handlers, [])
        self.assertEqual(logging.INFO, self.logger.level)

    def test_init_logger_debug_mode(self):
        # Test that the logger's level was set at 'DEBUG'
        bandit._init_logger(logging.DEBUG)
        self.assertEqual(logging.DEBUG, self.logger.level)


class BanditCLIMainTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.current_directory = os.getcwd()

    def tearDown(self):
        super().tearDown()
        os.chdir(self.current_directory)

    def test_get_options_from_ini_no_ini_path_no_target(self):
        # Test that no config options are loaded when no ini path or target
        # directory are provided
        self.assertIsNone(bandit._get_options_from_ini(None, []))

    def test_get_options_from_ini_empty_directory_no_target(self):
        # Test that no config options are loaded when an empty directory is
        # provided as the ini path and no target directory is provided
        ini_directory = self.useFixture(fixtures.TempDir()).path
        self.assertIsNone(bandit._get_options_from_ini(ini_directory, []))

    def test_get_options_from_ini_no_ini_path_no_bandit_files(self):
        # Test that no config options are loaded when no ini path is provided
        # and the target directory contains no bandit config files (.bandit)
        target_directory = self.useFixture(fixtures.TempDir()).path
        self.assertIsNone(
            bandit._get_options_from_ini(None, [target_directory])
        )

    def test_get_options_from_ini_no_ini_path_multi_bandit_files(self):
        # Test that bandit exits when no ini path is provided and the target
        # directory(s) contain multiple bandit config files (.bandit)
        target_directory = self.useFixture(fixtures.TempDir()).path
        second_config = "second_config_directory"
        os.mkdir(os.path.join(target_directory, second_config))
        bandit_config_one = os.path.join(target_directory, ".bandit")
        bandit_config_two = os.path.join(
            target_directory, second_config, ".bandit"
        )
        bandit_files = [bandit_config_one, bandit_config_two]
        for bandit_file in bandit_files:
            with open(bandit_file, "w") as fd:
                fd.write(bandit_config_content)
        self.assertRaisesRegex(
            SystemExit,
            "2",
            bandit._get_options_from_ini,
            None,
            [target_directory],
        )

    def test_init_extensions(self):
        # Test that an extension loader manager is returned
        self.assertEqual(ext_loader.MANAGER, bandit._init_extensions())

    def test_log_option_source_arg_val(self):
        # Test that the command argument value is returned when provided
        # with None or a string default value
        arg_val = "file"
        ini_val = "vuln"
        option_name = "aggregate"
        for default_val in (None, "default"):
            self.assertEqual(
                arg_val,
                bandit._log_option_source(
                    default_val, arg_val, ini_val, option_name
                ),
            )

    def test_log_option_source_ini_value(self):
        # Test that the ini value is returned when no command argument is
        # provided
        default_val = None
        ini_val = "vuln"
        option_name = "aggregate"
        self.assertEqual(
            ini_val,
            bandit._log_option_source(default_val, None, ini_val, option_name),
        )

    def test_log_option_source_ini_val_with_str_default_and_no_arg_val(self):
        # Test that the ini value is returned when no command argument is
        # provided
        default_val = "file"
        arg_val = "file"
        ini_val = "vuln"
        option_name = "aggregate"
        self.assertEqual(
            ini_val,
            bandit._log_option_source(
                default_val, arg_val, ini_val, option_name
            ),
        )

    def test_log_option_source_no_values(self):
        # Test that None is returned when no command argument or ini value are
        # provided
        option_name = "aggregate"
        self.assertIsNone(
            bandit._log_option_source(None, None, None, option_name)
        )

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_config_unopenable(self):
        # Test that bandit exits when a config file cannot be opened
        with mock.patch("bandit.core.config.__init__") as mock_bandit_config:
            mock_bandit_config.side_effect = utils.ConfigError("", "")
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_invalid_config(self):
        # Test that bandit exits when a config file contains invalid YAML
        # content
        with mock.patch(
            "bandit.core.config.BanditConfig.__init__"
        ) as mock_bandit_config:
            mock_bandit_config.side_effect = utils.ConfigError("", "")
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch("sys.argv", ["bandit", "-c", "bandit.yaml", "test"])
    def test_main_handle_ini_options(self):
        # Test that bandit handles cmdline args from a bandit.yaml file
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.cli.main._get_options_from_ini"
        ) as mock_get_opts:
            mock_get_opts.return_value = {
                "exclude": "/tmp",
                "skips": "skip_test",
                "tests": "some_test",
            }

            with mock.patch("bandit.cli.main.LOG.error") as err_mock:
                # SystemExit with code 2 when test not found in profile
                self.assertRaisesRegex(SystemExit, "2", bandit.main)
                self.assertEqual(
                    str(err_mock.call_args[0][0]),
                    "No tests would be run, please check the profile.",
                )

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-p", "bad", "test"]
    )
    def test_main_profile_not_found(self):
        # Test that bandit exits when an invalid profile name is provided
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        # assert a SystemExit with code 2
        with mock.patch("bandit.cli.main.LOG.error") as err_mock:
            self.assertRaisesRegex(SystemExit, "2", bandit.main)
            self.assertEqual(
                str(err_mock.call_args[0][0]),
                "Unable to find profile (bad) in config file: bandit.yaml",
            )

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "-b", "base.json", "test"]
    )
    def test_main_baseline_ioerror(self):
        # Test that bandit exits when encountering an IOError while reading
        # baseline data
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with open("base.json", "w") as fd:
            fd.write(bandit_baseline_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.populate_baseline"
        ) as mock_mgr_pop_bl:
            mock_mgr_pop_bl.side_effect = IOError
            # assert a SystemExit with code 2
            self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv",
        [
            "bandit",
            "-c",
            "bandit.yaml",
            "-b",
            "base.json",
            "-f",
            "csv",
            "test",
        ],
    )
    def test_main_invalid_output_format(self):
        # Test that bandit exits when an invalid output format is selected
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with open("base.json", "w") as fd:
            fd.write(bandit_baseline_content)
        # assert a SystemExit with code 2
        self.assertRaisesRegex(SystemExit, "2", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "test", "-o", "output"]
    )
    def test_main_exit_with_results(self):
        # Test that bandit exits when there are results
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 1
            # assert a SystemExit with code 1
            self.assertRaisesRegex(SystemExit, "1", bandit.main)

    @mock.patch(
        "sys.argv", ["bandit", "-c", "bandit.yaml", "test", "-o", "output"]
    )
    def test_main_exit_with_no_results(self):
        # Test that bandit exits when there are no results
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 0
            # assert a SystemExit with code 0
            self.assertRaisesRegex(SystemExit, "0", bandit.main)

    @mock.patch(
        "sys.argv",
        ["bandit", "-c", "bandit.yaml", "test", "-o", "output", "--exit-zero"],
    )
    def test_main_exit_with_results_and_with_exit_zero_flag(self):
        # Test that bandit exits with 0 on results and zero flag
        temp_directory = self.useFixture(fixtures.TempDir()).path
        os.chdir(temp_directory)
        with open("bandit.yaml", "w") as fd:
            fd.write(bandit_config_content)
        with mock.patch(
            "bandit.core.manager.BanditManager.results_count"
        ) as mock_mgr_results_ct:
            mock_mgr_results_ct.return_value = 1

            self.assertRaisesRegex(SystemExit, "0", bandit.main)


class BanditCLIMainIniTypingTests(testtools.TestCase):
    """End-to-end coverage for typed .bandit (INI) option handling.

    configparser only yields strings.  These tests exercise the full
    main() run against real files on disk to prove numeric and boolean INI
    values are coerced before being consumed, and that the CLI still wins
    when the same option is given in both places.
    """

    def _make_project(self, ini_content, nested=False, with_nosec=False):
        """Create a scan project and return (project_dir, ini_path)."""
        project_dir = self.useFixture(fixtures.TempDir()).path
        with open(os.path.join(project_dir, "top.py"), "w") as fd:
            fd.write("assert True\n")
        if nested:
            nested_dir = os.path.join(project_dir, "sub")
            os.mkdir(nested_dir)
            with open(os.path.join(nested_dir, "nested.py"), "w") as fd:
                fd.write("assert True\n")
        if with_nosec:
            with open(
                os.path.join(project_dir, "nosec_demo.py"), "w"
            ) as fd:
                fd.write("assert True  # nosec\n")
        ini_path = os.path.join(project_dir, ".bandit")
        with open(ini_path, "w") as fd:
            fd.write(ini_content)
        return project_dir, ini_path

    def _run_bandit(self, argv):
        """Run bandit.main with argv, returning (exit_code, parsed_json).

        The JSON report is written to a real temp file via -o: the json
        formatter inspects fileobj.name, which an in-memory stream lacks.
        """
        report_path = os.path.join(
            self.useFixture(fixtures.TempDir()).path, "report.json"
        )
        argv = argv + ["-o", report_path]
        with mock.patch("sys.argv", argv):
            try:
                bandit.main()
                exit_code = 0
            except SystemExit as exc:
                exit_code = exc.code
        with open(report_path) as fd:
            return exit_code, json.load(fd)

    def test_ini_numeric_threshold_outputs_report(self):
        # A numeric threshold written in .bandit must be coerced to int so
        # the report is produced instead of crashing before output.
        project_dir, ini_path = self._make_project(
            "[bandit]\nlevel = 2\nconfidence = 1\n"
        )
        exit_code, report = self._run_bandit(
            [
                "bandit",
                "--ini",
                ini_path,
                "-f",
                "json",
                os.path.join(project_dir, "top.py"),
            ]
        )
        # Real finding -> exit 1 (a crash used to surface as the same code,
        # but now the report exists, proving the run completed normally).
        self.assertEqual(1, exit_code)
        self.assertEqual(
            ["B101"], [r["test_id"] for r in report["results"]]
        )

    def test_ini_recursive_false_scans_top_level_only(self):
        # recursive = false must mean "do not descend into subdirectories".
        project_dir, ini_path = self._make_project(
            "[bandit]\nrecursive = false\n", nested=True
        )
        exit_code, report = self._run_bandit(
            ["bandit", "--ini", ini_path, "-f", "json", project_dir]
        )
        self.assertEqual(0, exit_code)
        self.assertEqual([], report["results"])

        # The top-level file itself, when named explicitly, is still scanned,
        # proving the flag narrows discovery rather than disabling it.
        exit_code, report = self._run_bandit(
            [
                "bandit",
                "--ini",
                ini_path,
                "-f",
                "json",
                os.path.join(project_dir, "top.py"),
            ]
        )
        self.assertEqual(1, exit_code)
        self.assertEqual(
            ["top.py"],
            [os.path.basename(r["filename"]) for r in report["results"]],
        )

    def test_ini_ignore_nosec_false_keeps_suppression(self):
        # ignore-nosec = false must keep honoring # nosec comments.
        project_dir, ini_path = self._make_project(
            "[bandit]\nignore-nosec = false\n", with_nosec=True
        )
        exit_code, report = self._run_bandit(
            [
                "bandit",
                "--ini",
                ini_path,
                "-f",
                "json",
                os.path.join(project_dir, "nosec_demo.py"),
            ]
        )
        self.assertEqual(0, exit_code)
        self.assertEqual([], report["results"])

        # The same project with --ignore-nosec on the CLI must override the
        # INI value and surface the suppressed finding.
        exit_code, report = self._run_bandit(
            [
                "bandit",
                "--ini",
                ini_path,
                "--ignore-nosec",
                "-f",
                "json",
                os.path.join(project_dir, "nosec_demo.py"),
            ]
        )
        self.assertEqual(1, exit_code)
        self.assertEqual(
            ["B101"], [r["test_id"] for r in report["results"]]
        )

    def test_cli_takes_precedence_over_ini_same_option(self):
        # When the same option appears in both places, the CLI wins.
        # INI says recursive = false, CLI -r must still recurse.
        project_dir, ini_path = self._make_project(
            "[bandit]\nrecursive = false\n", nested=True
        )
        exit_code, report = self._run_bandit(
            [
                "bandit",
                "--ini",
                ini_path,
                "-r",
                "-f",
                "json",
                project_dir,
            ]
        )
        self.assertEqual(1, exit_code)
        scanned = sorted(
            os.path.basename(r["filename"]) for r in report["results"]
        )
        self.assertEqual(["nested.py", "top.py"], scanned)

        # Conversely, INI recursive = true without -r recurses on its own.
        true_ini = os.path.join(project_dir, ".bandit-true")
        with open(true_ini, "w") as fd:
            fd.write("[bandit]\nrecursive = true\n")
        exit_code, report = self._run_bandit(
            ["bandit", "--ini", true_ini, "-f", "json", project_dir]
        )
        self.assertEqual(1, exit_code)
        self.assertEqual(2, len(report["results"]))


class BanditCLIIniCoercionHelperTests(testtools.TestCase):
    """Direct unit tests for the INI type-coercion helpers."""

    def test_coerce_ini_bool(self):
        for true_value in ("true", "TRUE", " True ", "1", "yes", "on"):
            self.assertTrue(
                utils.coerce_ini_bool(true_value, "recursive"),
                f"{true_value!r} should coerce to True",
            )
        for false_value in ("false", "FALSE", " False ", "0", "no", "off"):
            self.assertFalse(
                utils.coerce_ini_bool(false_value, "recursive"),
                f"{false_value!r} should coerce to False",
            )
        self.assertIsNone(utils.coerce_ini_bool(None, "recursive"))
        self.assertTrue(utils.coerce_ini_bool(True, "recursive"))
        self.assertFalse(utils.coerce_ini_bool(False, "recursive"))

    def test_coerce_ini_bool_rejects_garbage(self):
        self.assertRaises(
            utils.IniConfigError,
            utils.coerce_ini_bool,
            "maybe",
            "recursive",
        )

    def test_coerce_ini_int(self):
        self.assertEqual(2, utils.coerce_ini_int("2", "level"))
        self.assertEqual(3, utils.coerce_ini_int(" 3 ", "confidence"))
        self.assertIsNone(utils.coerce_ini_int(None, "level"))
        self.assertEqual(4, utils.coerce_ini_int(4, "level"))

    def test_coerce_ini_int_rejects_garbage(self):
        for bad_value in ("high", "1.5", ""):
            self.assertRaises(
                utils.IniConfigError,
                utils.coerce_ini_int,
                bad_value,
                "level",
            )
        self.assertRaises(
            utils.IniConfigError,
            utils.coerce_ini_int,
            True,
            "level",
        )
