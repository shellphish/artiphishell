# pylint: disable=too-many-arguments
import base64
import os
from hashlib import sha256
from unittest import mock
from uuid import uuid4

import pytest
from sqlalchemy import insert, select, update
from vyper import v

from competition_api.audit.types import EventType, GPSubmissionInvalidReason
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.models.types import FeedbackStatus
from tests.conftest import FAKE_CP_NAME


class TestGP:
    @staticmethod
    @pytest.mark.parametrize(
        "body,invalid_reason",
        [
            ({"data": "ZmFrZQo="}, None),
            ({"data": "A" * (1024 * 100)}, None),  # 100KiB input
            ({"data": "ZmFrZQo="}, GPSubmissionInvalidReason.INVALID_VDS_ID),
            ({"data": "ZmFrZQo="}, GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM),
        ],
    )
    async def test_post(
        client,
        body,
        invalid_reason,
        fake_accepted_vds,
        auth_header,
        mock_get_auditor,
        auditor,
    ):
        body["cpv_uuid"] = (
            str(uuid4())
            if invalid_reason == GPSubmissionInvalidReason.INVALID_VDS_ID
            else str(fake_accepted_vds["cpv_uuid"])
        )

        if invalid_reason == GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM:
            async with db_session() as db:
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(
                        VulnerabilityDiscovery.cpv_uuid == fake_accepted_vds["cpv_uuid"]
                    )
                    .values(team_id=uuid4())
                )

        with mock.patch(
            "competition_api.endpoints.gp.gp.TaskRunner", autospec=True
        ), mock.patch("competition_api.endpoints.gp.gp.get_auditor", mock_get_auditor):
            resp = client.post("/submission/gp/", json=body, headers=auth_header)

        if invalid_reason:
            assert resp.status_code == 404
        else:
            assert resp.status_code == 200

        resp = resp.json()

        async with db_session() as db:
            db_row = (await db.execute(select(GeneratedPatch))).fetchall()
        assert len(db_row) == 1
        db_row = db_row[0][0]

        data = base64.b64decode(body["data"])
        data_hash = sha256(data).hexdigest()

        if not invalid_reason:
            assert resp["gp_uuid"] == str(db_row.id)
            assert resp["status"] == FeedbackStatus.PENDING.value
            assert resp["patch_size"] == len(data)
            assert str(db_row.cpv_uuid) == body["cpv_uuid"]
            assert db_row.data_sha256 == data_hash
            assert db_row.status == FeedbackStatus.PENDING
        else:
            assert not resp.get("gp_uuid")

        submission_evt = auditor.get_events(EventType.GP_SUBMISSION)
        assert submission_evt
        submission_evt = submission_evt[0]

        assert submission_evt.patch_sha256 == data_hash

        with open(
            os.path.join(v.get("flatfile_dir"), submission_evt.patch_sha256),
            "rb",
        ) as f:
            assert f.read() == data

        assert str(submission_evt.submitted_cpv_uuid) == body["cpv_uuid"]

        invalid_evt = auditor.get_events(EventType.GP_SUBMISSION_INVALID)
        if invalid_reason:
            assert invalid_evt
            invalid_evt = invalid_evt[0]
            assert invalid_evt.reason == invalid_reason
        else:
            assert not invalid_evt

    @staticmethod
    async def test_post_wrong_return(
        client,
        fake_accepted_vds,
        auth_header,
        mock_get_auditor,
    ):
        body = {"data": "ZmFrZQo=", "cpv_uuid": str(fake_accepted_vds["cpv_uuid"])}

        # Boost the odds that the DB returns the wrong row to the API endpoint
        wrong_ids = set()
        for _ in range(100):
            async with db_session() as db:
                cpv_uuid = uuid4()
                await db.execute(
                    insert(VulnerabilityDiscovery).values(
                        team_id=uuid4(),
                        cpv_uuid=cpv_uuid,
                        cp_name=FAKE_CP_NAME,
                        pou_commit_sha1="not",
                        pou_sanitizer="id_1",
                        pov_harness="id_1",
                        pov_data_sha256="not",
                    )
                )
                wrong_ids.add(
                    str(
                        (
                            await db.execute(
                                insert(GeneratedPatch)
                                .values(cpv_uuid=cpv_uuid, data_sha256="not")
                                .returning(GeneratedPatch.id)
                            )
                        ).fetchall()[0][0]
                    )
                )

        with mock.patch(
            "competition_api.endpoints.gp.gp.TaskRunner", autospec=True
        ), mock.patch("competition_api.endpoints.gp.gp.get_auditor", mock_get_auditor):
            resp = client.post("/submission/gp/", json=body, headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        assert resp["gp_uuid"] not in wrong_ids

    @staticmethod
    @pytest.mark.parametrize(
        "body",
        [{"data": "ZmFrZQo="}],
    )
    def test_post_bad_uuid(client, body, fake_vds, auth_header):
        body["cpv_uuid"] = fake_vds.get("cpv_uuid")
        resp = client.post("/submission/gp/", json=body, headers=auth_header)

        assert resp.status_code == 422

    @staticmethod
    @pytest.mark.parametrize(
        "body",
        [
            {
                "data": base64.b64encode(b"\00" * (1024 * 100 + 1)).decode("utf8")
            },  # 100KiB + 1 byte input
        ],
    )
    def test_post_invalid_format(
        client,
        body,
        fake_accepted_vds,
        auth_header,
        mock_get_auditor,
    ):
        body["cpv_uuid"] = str(fake_accepted_vds["cpv_uuid"])

        with mock.patch(
            "competition_api.endpoints.gp.gp.TaskRunner", autospec=True
        ), mock.patch("competition_api.endpoints.gp.gp.get_auditor", mock_get_auditor):
            resp = client.post("/submission/gp/", json=body, headers=auth_header)

        assert resp.status_code == 422

    @staticmethod
    def test_get(client, fake_gp, auth_header):
        resp = client.get(f"/submission/gp/{str(fake_gp['id'])}", headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        assert resp["status"] == fake_gp["status"]
        assert resp["gp_uuid"] == str(fake_gp["id"])

    @staticmethod
    async def test_get_other_team(client, fake_gp, auth_header):
        async with db_session() as db:
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.cpv_uuid == fake_gp["cpv_uuid"])
                .values(team_id=uuid4())
            )

        resp = client.get(f"/submission/gp/{str(fake_gp['id'])}", headers=auth_header)

        assert resp.status_code == 404
