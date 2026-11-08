"""
Automated Security & Configuration Tests for Docker and Linux Host Installation.
Validates Dockerfile, docker-compose.yml, install.sh, pyproject.toml, and component trust.
"""

import os
import re
import subprocess
import unittest

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class TestDockerAndLinuxInstallation(unittest.TestCase):
    """Verifies Docker, Compose v2, and Linux host installation compliance."""

    def test_01_dockerfile_compliance_and_security(self):
        """Verifies Dockerfile conforms to official Docker best practices and CIS benchmark."""
        dockerfile_path = os.path.join(ROOT_DIR, "Dockerfile")
        self.assertTrue(os.path.exists(dockerfile_path), "Dockerfile must exist")

        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        # 1. Base image must be official, minimal, security-supported
        self.assertIn("python:3.11-slim-bookworm", content)

        # 2. Multi-stage build
        self.assertIn("AS builder", content)
        self.assertIn("AS runner", content)

        # 3. Non-root user execution
        self.assertTrue(
            "USER 10001:10001" in content or "USER adproxy" in content,
            "Dockerfile must enforce non-root execution",
        )

        # 4. Healthcheck directive
        self.assertIn("HEALTHCHECK", content)
        self.assertIn("/health", content)

        # 5. Exposed LDAPS port
        self.assertIn("EXPOSE 10636", content)

        # 6. Python performance environment variables
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", content)
        self.assertIn("PYTHONUNBUFFERED=1", content)

    def test_02_docker_compose_specification_v2_compliance(self):
        """Verifies docker-compose.yml complies with modern Compose v2 spec without obsolete keys."""
        compose_path = os.path.join(ROOT_DIR, "docker-compose.yml")
        self.assertTrue(os.path.exists(compose_path), "docker-compose.yml must exist")

        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Modern Compose v2 spec does NOT use obsolete version: '3.8' string
        self.assertFalse(
            re.search(r"^\s*version:\s*['\"]", content, re.MULTILINE),
            "Modern Docker Compose v2 specification must not contain obsolete 'version:' string",
        )

        # Security controls
        self.assertIn("no-new-privileges:true", content)
        self.assertIn("cap_drop:", content)
        self.assertIn("read_only: true", content)

        # Scratch memory tmpfs
        self.assertIn("tmpfs:", content)
        self.assertIn("/tmp", content)

        # Volume mounts for persistence and security
        self.assertIn("./logs:/app/logs:rw", content)
        self.assertIn("./certs:/app/certs:ro", content)
        self.assertIn("./ad_proxy/config.yaml:/app/ad_proxy/config.yaml:ro", content)

        # Healthcheck
        self.assertIn("healthcheck:", content)

    def test_03_dockerignore_configuration(self):
        """Verifies .dockerignore excludes sensitive secrets, build artifacts, and caches."""
        dockerignore_path = os.path.join(ROOT_DIR, ".dockerignore")
        self.assertTrue(os.path.exists(dockerignore_path), ".dockerignore must exist")

        with open(dockerignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn(".git", content)
        self.assertIn("__pycache__", content)
        self.assertIn("node_modules", content)
        self.assertIn(".env", content)

    def test_04_linux_installer_bash_syntax_and_capabilities(self):
        """Verifies install.sh has valid bash syntax and checks requirements."""
        install_sh = os.path.join(ROOT_DIR, "install.sh")
        self.assertTrue(os.path.exists(install_sh), "install.sh must exist")

        # Validate syntax via bash -n
        res = subprocess.run(["bash", "-n", install_sh], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"install.sh has syntax errors: {res.stderr}")

        with open(install_sh, "r", encoding="utf-8") as f:
            content = f.read()

        # Checks Linux and Python
        self.assertIn("uname -s", content)
        self.assertIn("python3", content)
        self.assertIn("ad_proxy.cli --run-tests", content)
        self.assertIn("ad_proxy.cli --check-config", content)

    def test_05_systemd_service_unit_compliance(self):
        """Verifies ad-proxy.service contains systemd sandboxing hardening."""
        service_path = os.path.join(ROOT_DIR, "ad-proxy.service")
        self.assertTrue(os.path.exists(service_path), "ad-proxy.service must exist")

        with open(service_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("NoNewPrivileges=true", content)
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("ProtectHome=true", content)
        self.assertIn("PrivateTmp=true", content)
        self.assertIn("User=adproxy", content)
        self.assertIn("ExecStart=", content)

    def test_06_package_specifications(self):
        """Verifies pyproject.toml and setup.py are valid and reference official dependencies."""
        pyproject_path = os.path.join(ROOT_DIR, "pyproject.toml")
        setup_path = os.path.join(ROOT_DIR, "setup.py")
        self.assertTrue(os.path.exists(pyproject_path), "pyproject.toml must exist")
        self.assertTrue(os.path.exists(setup_path), "setup.py must exist")

        with open(pyproject_path, "r", encoding="utf-8") as f:
            pyproject_content = f.read()

        self.assertIn("ad-ldaps-proxy", pyproject_content)
        self.assertIn("ldap3>=2.9.1", pyproject_content)
        self.assertIn("pyyaml>=6.0.1", pyproject_content)
        self.assertIn("cryptography>=42.0.0", pyproject_content)
        self.assertIn("hvac>=2.1.0", pyproject_content)

    def test_07_docker_install_script_syntax_and_options(self):
        """Verifies docker-install.sh script exists, has valid bash syntax, and provides options."""
        docker_install_sh = os.path.join(ROOT_DIR, "docker-install.sh")
        self.assertTrue(os.path.exists(docker_install_sh), "docker-install.sh must exist")

        res = subprocess.run(["bash", "-n", docker_install_sh], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"docker-install.sh has syntax errors: {res.stderr}")

        with open(docker_install_sh, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("--headless", content)
        self.assertIn("--fullstack", content)
        self.assertIn("docker compose", content)
        self.assertIn("docker-compose.yml", content)
        self.assertIn("docker-compose.fullstack.yml", content)

    def test_08_docker_compose_fullstack_specification_v2(self):
        """Verifies docker-compose.fullstack.yml adheres to Compose v2 spec and CIS security baseline."""
        fullstack_compose = os.path.join(ROOT_DIR, "docker-compose.fullstack.yml")
        self.assertTrue(os.path.exists(fullstack_compose), "docker-compose.fullstack.yml must exist")

        with open(fullstack_compose, "r", encoding="utf-8") as f:
            content = f.read()

        # Modern Compose v2 spec does NOT use obsolete version: '3.8' string
        self.assertFalse(
            re.search(r"^\s*version:\s*['\"]", content, re.MULTILINE),
            "docker-compose.fullstack.yml must not contain obsolete 'version:' string",
        )
        self.assertIn("3000:3000", content)
        self.assertIn("10636:10636", content)
        self.assertIn("no-new-privileges:true", content)
        self.assertIn("healthcheck:", content)
        self.assertIn("user: \"10001:10001\"", content)

    def test_09_official_docker_practices_no_obsolete_directives(self):
        """Verifies Dockerfiles follow official modern Docker instructions (no MAINTAINER, proper LABEL, etc)."""
        dockerfiles = ["Dockerfile", "Dockerfile.fullstack"]
        for df in dockerfiles:
            df_path = os.path.join(ROOT_DIR, df)
            self.assertTrue(os.path.exists(df_path), f"{df} must exist")
            with open(df_path, "r", encoding="utf-8") as f:
                content = f.read()
            # MAINTAINER is deprecated in Docker; LABEL must be used instead
            self.assertFalse(re.search(r"^\s*MAINTAINER\s+", content, re.MULTILINE), f"{df} must not use obsolete MAINTAINER")
            # Multi-stage FROM
            self.assertIn("AS ", content)
            # Must run as unprivileged user
            self.assertIn("USER 10001:10001", content)

    def test_10_linux_host_install_execution_verification(self):
        """Verifies install.sh runs cleanly and validates Linux installation without errors."""
        install_sh = os.path.join(ROOT_DIR, "install.sh")
        # Run install script in subshell with SKIP_TESTS=1 to prevent infinite recursion
        env = dict(os.environ)
        env["SKIP_TESTS"] = "1"
        res = subprocess.run(["bash", install_sh], capture_output=True, text=True, cwd=ROOT_DIR, env=env)
        self.assertEqual(res.returncode, 0, f"install.sh execution failed: {res.stderr}\n{res.stdout}")
        self.assertIn("INSTALLATION & SECURITY VALIDATION COMPLETED SUCCESSFULLY!", res.stdout)
        self.assertIn("[OK] Verified Linux Host environment", res.stdout)
        self.assertIn("[OK] Detected supported Python version", res.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)

