# pylint: disable=too-many-arguments,unused-argument

import base64
import os
from hashlib import sha256
from unittest import mock
from uuid import uuid4

import pytest
from sqlalchemy import select, update
from vyper import v

from competition_api.audit.types import EventType
from competition_api.db import VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile
from competition_api.models.types import FeedbackStatus
from tests.conftest import FAKE_CP_NAME


class TestVDS:
    @staticmethod
    @pytest.mark.parametrize(
        "body,return_code",
        [
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {"harness": "id_1", "data": "ZmFrZQo="},
                },
                200,
            ),
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {
                        "harness": "id_1",
                        "data": "i4uLi4WLi4uLi4uLi4uLi4uLi4xQi4uLi4uLjIuLiw==",  # non-text patch
                    },
                },
                200,
            ),
            ({}, 422),
            (
                {
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {
                        "harness": "id_1",
                        "data": "i4uLi4WLi4uLi4uLi4uLi4uLi4xQi4uLi4uLjIuLiw==",  # non-text patch
                    },
                },
                422,
            ),
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pov": {
                        "harness": "id_1",
                        "data": "i4uLi4WLi4uLi4uLi4uLi4uLi4xQi4uLi4uLjIuLiw==",  # non-text patch
                    },
                },
                422,
            ),
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                },
                422,
            ),
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {
                        "harness": "id_1",
                        "data": base64.b64encode(b"\00" * (1024 * 1024 * 2 + 1)).decode(
                            "utf8"
                        ),  # 2MiB + 1 byte input
                    },
                },
                422,
            ),
            (
                {
                    "cp_name": FAKE_CP_NAME,
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {
                        "harness": "id_1",
                        "data": base64.b64encode(b"\00" * (1024 * 1024 * 2)).decode(
                            "utf8"
                        ),  # 2MiB input
                    },
                },
                200,
            ),
            (
                {
                    "cp_name": "not-a-real-cp",
                    "pou": {
                        "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                        "sanitizer": "id_1",
                    },
                    "pov": {
                        "harness": "id_1",
                        "data": "i4uLi4WLi4uLi4uLi4uLi4uLi4xQi4uLi4uLjIuLiw==",  # non-text patch
                    },
                },
                404,
            ),
        ],
    )
    async def test_post(
        client, body, return_code, auth_header, mock_get_auditor, auditor, repo
    ):
        with mock.patch(
            "competition_api.endpoints.vds.vds.TaskRunner", autospec=True
        ), mock.patch(
            "competition_api.endpoints.vds.vds.get_auditor", mock_get_auditor
        ):
            resp = client.post("/submission/vds/", json=body, headers=auth_header)

        assert resp.status_code == return_code

        success = return_code == 200

        resp = resp.json()

        async with db_session() as db:
            db_row = (await db.execute(select(VulnerabilityDiscovery))).fetchall()
        assert len(db_row) == (
            1 if success or body.get("cp_name") == "not-a-real-cp" else 0
        )

        if success:
            data = base64.b64decode(body.get("pov").get("data"))
            data_hash = sha256(data).hexdigest()

            db_row = db_row[0][0]

            assert resp["vd_uuid"] == str(db_row.id)
            assert resp["status"] == FeedbackStatus.PENDING.value
            assert resp["cp_name"] == body["cp_name"]

            assert db_row.pou_commit_sha1.lower() == body["pou"]["commit_sha1"].lower()
            assert db_row.pou_sanitizer == body["pou"]["sanitizer"]
            assert db_row.pov_harness == body["pov"]["harness"]
            assert db_row.pov_data_sha256 == data_hash
            assert db_row.status == FeedbackStatus.PENDING

            submission_evt = auditor.get_events(EventType.VD_SUBMISSION)
            assert submission_evt
            submission_evt = submission_evt[0]

            assert submission_evt.harness == body["pov"]["harness"]
            assert submission_evt.pou_commit == body["pou"]["commit_sha1"]
            assert submission_evt.sanitizer == body["pou"]["sanitizer"]

            assert submission_evt.pov_blob_sha256 == data_hash

            with open(
                os.path.join(v.get("flatfile_dir"), submission_evt.pov_blob_sha256),
                "rb",
            ) as f:
                assert f.read() == data
        else:
            assert not auditor.get_events(EventType.VD_SUBMISSION)

    @staticmethod
    @pytest.mark.parametrize(
        "row",
        [
            {
                "cp_name": "somecp",
                "pou_commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                "pou_sanitizer": "id_1",
                "pov_harness": "id_1",
            }
        ],
    )
    async def test_get(client, row, creds, auth_header):
        blob = Flatfile(contents=b"fake\n")
        await blob.write()

        row["pov_data_sha256"] = blob.sha256

        row["team_id"] = creds[0]
        async with db_session() as db:
            db_row = await db.execute(VulnerabilityDiscovery.insert_returning(**row))
        db_row = db_row.all()[0]

        resp = client.get(f"/submission/vds/{str(db_row.id)}", headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        assert resp["status"] == db_row.status.value
        assert resp["vd_uuid"] == str(db_row.id)

    @staticmethod
    async def test_get_other_team(client, fake_vds, auth_header):
        async with db_session() as db:
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_vds["id"])
                .values(team_id=uuid4())
            )

        resp = client.get(f"/submission/vds/{str(fake_vds['id'])}", headers=auth_header)

        assert resp.status_code == 404
