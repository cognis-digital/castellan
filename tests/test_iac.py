"""IaC importer tests: Terraform, CloudFormation, Kubernetes, compose, dispatch."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from castellan.iac import terraform, cloudformation, kubernetes, compose  # noqa: E402
from castellan import importers  # noqa: E402
from castellan.core import build_threat_model  # noqa: E402

TF = '''
resource "aws_s3_bucket" "data" { bucket = "my-data" }
resource "aws_db_instance" "main" { storage_encrypted = true }
resource "aws_lambda_function" "api" { function_name = "api" }
'''

CFN = '''
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  AppBucket:
    Type: AWS::S3::Bucket
  AppFunction:
    Type: AWS::Lambda::Function
  AppTable:
    Type: AWS::DynamoDB::Table
'''

K8S = '''
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          securityContext:
            privileged: true
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
'''

COMPOSE = '''
services:
  web:
    image: nginx
    ports: ["80:80"]
  db:
    image: postgres:16
'''


class TerraformTests(unittest.TestCase):
    def test_parse_resources(self):
        spec = terraform.import_text(TF)
        names = {e.name for e in spec.elements}
        self.assertIn("data", names)
        self.assertIn("api", names)
        # encrypted db gets an encrypt control
        db = spec.element("main")
        self.assertIn("encrypt", db.metadata.get("controls", []))

    def test_models(self):
        m = build_threat_model(terraform.import_text(TF))
        self.assertGreater(m.summary()["total_threats"], 0)


class CloudFormationTests(unittest.TestCase):
    def test_parse_yaml(self):
        spec = cloudformation.import_text(CFN)
        labels = {e.raw_type for e in spec.elements}
        self.assertTrue(any("object store" in x or "database" in x or "function" in x
                            for x in labels))


class KubernetesTests(unittest.TestCase):
    def test_privileged_flagged(self):
        spec = kubernetes.import_text(K8S)
        web = spec.element("web")
        self.assertEqual(web.metadata.get("exposure"), "privileged")
        self.assertIsNotNone(spec.element("app-secret"))


class ComposeTests(unittest.TestCase):
    def test_services_and_store(self):
        spec = compose.import_text(COMPOSE)
        db = spec.element("db")
        self.assertEqual(db.type, "datastore")
        web = spec.element("web")
        self.assertEqual(web.metadata.get("exposure"), "published-port")


class DispatchTests(unittest.TestCase):
    def test_detect(self):
        self.assertEqual(importers.detect("main.tf", TF), "terraform")
        self.assertEqual(importers.detect("t.yaml", CFN), "cloudformation")
        self.assertEqual(importers.detect("d.yaml", K8S), "kubernetes")
        self.assertEqual(importers.detect("docker-compose.yml", COMPOSE), "compose")

    def test_import_directory(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        spec = importers.import_path(os.path.join(here, "deploy"))
        self.assertTrue(spec.elements)
        m = build_threat_model(spec)
        self.assertGreater(m.summary()["total_threats"], 0)


if __name__ == "__main__":
    unittest.main()
