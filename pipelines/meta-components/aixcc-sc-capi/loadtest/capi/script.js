import http from "k6/http";
import encoding from "k6/encoding";
import { group, check, sleep } from "k6";

import { parse } from "k6/x/yaml";

const BASE_URL = __ENV.AIXCC_API_HOSTNAME; // eslint-disable-line

const USERS = parse(open("/app/loadtest_config.yaml")).auth.preload;
function* nextUser() {
  for (const [tokenId, token] of Object.entries(USERS)) {
    const creds = { tokenId, token };
    console.log(`Returning new user ${tokenId}`);
    yield creds;
  }
}
const userIterator = nextUser();

export default function () {
  /*
   * This function pulls a user off of the list and then runs a bunch of request sequences in
   * random order. Each request sequence has a total number of repetitions. The resulting effect is
   * that the user hits the health check a bunch while submitting broken & invalid inputs and one
   * working combination of VDS and GP.
   */

  const user = userIterator.next().value;
  const headers = {
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Authorization:
        "Basic " + encoding.b64encode(`${user.tokenId}:${user.token}`),
    },
  };

  let functions = [
    {
      repetitions: 1,
      group: "successful complete workflow",
      function: () => {
        const vdsBody = {
          cp_name: "Mock CP",
          pou: {
            commit_sha1: "9d38fc63bb9ffbc65f976cbca45e096bad3b30e1",
            sanitizer: "id_1",
          },
          pov: {
            harness: "id_1",
            data: "3V61NcZ2GZ4RaOPPdlxvBUelvZZvu7ykuu85SogxkrQMaXZpnyZOcA==",
          },
        };
        const vdsSubmissionResp = http.post(
          BASE_URL + "/submission/vds/",
          JSON.stringify(vdsBody),
          headers,
        );

        console.log(
          `VDS submission resp before check: ${vdsSubmissionResp.status} ${JSON.stringify(vdsSubmissionResp.json())}`,
        );
        check(vdsSubmissionResp, {
          "Successful vds submission": (r) =>
            r.status === 200 && r.json("vd_uuid"),
        });

        const vdUuid = vdsSubmissionResp.json("vd_uuid");
        let vdsStatusResp = http.get(
          BASE_URL + `/submission/vds/${vdUuid}`,
          headers,
        );

        console.log(
          `VDS status resp before first pending check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
        );
        check(vdsStatusResp, {
          "Successful submission pending status check": (r) =>
            r.status === 200 && r.json("status") === "pending",
        });

        console.log("Waiting for VDS test to complete");
        console.log(`Status is ${vdsStatusResp.json("status")}`);
        while (vdsStatusResp.json("status") === "pending") {
          sleep(5);
          vdsStatusResp = http.get(
            BASE_URL + `/submission/vds/${vdUuid}`,
            headers,
          );
          console.log(
            `VDS status resp before pending check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
          );
          check(vdsStatusResp, {
            "VDS status check response 200": (r) => r.status === 200,
          });
          console.log(`Status is ${vdsStatusResp.json("status")}`);
        }

        console.log(
          `VDS status resp before accepted check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
        );
        check(vdsStatusResp, {
          "Successful VDS submission accepted status check": (r) =>
            r.status === 200 &&
            r.json("status") === "accepted" &&
            r.json("cpv_uuid"),
        });

        const cpvUuid = vdsStatusResp.json("cpv_uuid");
        const gpBody = {
          cpvUuid,
          data: "ZGlmZiAtLWdpdCBhL21vY2tfdnAuYyBiL21vY2tfdnAuYwppbmRleCA1NmNmOGZkLi5hYmI3M2NkIDEwMDY0NAotLS0gYS9tb2NrX3ZwLmMKKysrIGIvbW9ja192cC5jCkBAIC0xMSw3ICsxMSw4IEBAIGludCBtYWluKCkKICAgICAgICAgcHJpbnRmKCJpbnB1dCBpdGVtOiIpOwogICAgICAgICBidWZmID0gJml0ZW1zW2ldWzBdOwogICAgICAgICBpKys7Ci0gICAgICAgIGZnZXRzKGJ1ZmYsIDQwLCBzdGRpbik7CisgICAgICAgIGZnZXRzKGJ1ZmYsIDksIHN0ZGluKTsKKyAgICAgICAgaWYgKGk9PTMpe2J1ZmZbMF09IDA7fQogICAgICAgICBidWZmW3N0cmNzcG4oYnVmZiwgIlxuIildID0gMDsKICAgICB9d2hpbGUoc3RybGVuKGJ1ZmYpIT0wKTsKICAgICBpLS07Cg==",
        };
        console.log(`Submitting GP for issued CPV ${cpvUuid}`);
        const gpSubmissionResp = http.post(
          BASE_URL + "/submission/gp/",
          JSON.stringify(gpBody),
          headers,
        );

        console.log(
          `GP submission resp before check: ${gpSubmissionResp.status} ${JSON.stringify(gpSubmissionResp.json())}`,
        );
        check(gpSubmissionResp, {
          "Successful GP submission": (r) =>
            r.status === 200 && r.json("gp_uuid"),
        });

        const gpUuid = gpSubmissionResp.json("gp_uuid");
        let gpStatusResp = http.get(
          BASE_URL + `/submission/gp/${gpUuid}`,
          headers,
        );

        console.log(
          `GP status resp before first pending check: ${gpStatusResp.status} ${JSON.stringify(gpStatusResp.json())}`,
        );
        check(gpStatusResp, {
          "Successful GP submission pending status check": (r) =>
            r.status === 200 && r.json("status") === "pending",
        });

        console.log("Waiting for GP test to complete");
        console.log(`Status is ${gpStatusResp.json("status")}`);
        while (gpStatusResp.json("status") === "pending") {
          sleep(5);
          gpStatusResp = http.get(
            BASE_URL + `/submission/gp/${gpUuid}`,
            headers,
          );

          console.log(
            `GP status resp before pending check: ${gpStatusResp.status} ${JSON.stringify(gpStatusResp.json())}`,
          );
          check(gpStatusResp, {
            "GP status check response 200": (r) => r.status === 200,
          });
          console.log(`Status is ${gpStatusResp.json("status")}`);
        }

        console.log(
          `GP status resp before accepted check: ${gpStatusResp.status} ${JSON.stringify(gpStatusResp.json())}`,
        );

        check(gpStatusResp, {
          "Successful GP submission accepted status check": (r) =>
            r.status === 200 && r.json("status") === "accepted",
        });
      },
    },
    {
      repetitions: 100,
      group: "/",
      function: () => {
        const url = BASE_URL + "/";
        const request = http.get(url);

        check(request, {
          "Successful Response": (r) => r.status === 200,
        });
      },
    },
    {
      repetitions: 100,
      group: "health",
      function: () => {
        const url = BASE_URL + "/health/";
        const request = http.get(url);

        check(request, {
          "Successful Response": (r) => r.status === 200,
        });
      },
    },
    {
      repetitions: 10,
      group: "duplicate VDS",
      function: () => {
        const vdsBody = {
          cp_name: "Mock CP",
          pou: {
            commit_sha1: "9d38fc63bb9ffbc65f976cbca45e096bad3b30e1",
            sanitizer: "id_1",
          },
          pov: {
            harness: "id_1",
            data: "3V61NcZ2GZ4RaOPPdlxvBUelvZZvu7ykuu85SogxkrQMaXZpnyZOcA==",
          },
        };
        const vdsSubmissionResp = http.post(
          BASE_URL + "/submission/vds/",
          JSON.stringify(vdsBody),
          headers,
        );

        check(vdsSubmissionResp, {
          "Successful vds submission": (r) =>
            r.status === 200 && r.json("vd_uuid"),
        });

        const vdUuid = vdsSubmissionResp.json("vd_uuid");
        let vdsStatusResp = http.get(
          BASE_URL + `/submission/vds/${vdUuid}`,
          headers,
        );

        check(vdsStatusResp, {
          "Successful submission pending status check": (r) =>
            r.status === 200 && r.json("status") === "pending",
        });

        console.log("Waiting for VDS test to complete");
        console.log(`Status is ${vdsStatusResp.json("status")}`);
        while (vdsStatusResp.json("status") === "pending") {
          sleep(5);
          vdsStatusResp = http.get(
            BASE_URL + `/submission/vds/${vdUuid}`,
            headers,
          );
          check(vdsStatusResp, {
            "VDS status check response 200": (r) => r.status === 200,
          });
          console.log(`Status is ${vdsStatusResp.json("status")}`);
        }

        check(vdsStatusResp, {
          "Successful VDS submission rejected status check": (r) =>
            r.status === 200 && r.json("status") === "rejected",
        });
      },
    },
    {
      repetitions: 30,
      group: "broken VDS",
      function: () => {
        const vdsBody = {
          cp_name: "Mock CP",
          pou: {
            commit_sha1: "9d38fc63bb9ffbc65f976cbca45e096bad3b30e1",
            sanitizer: "id_1",
          },
          pov: {
            harness: "id_1",
          },
        };
        const vdsSubmissionResp = http.post(
          BASE_URL + "/submission/vds/",
          JSON.stringify(vdsBody),
          headers,
        );

        check(vdsSubmissionResp, {
          "Successful vds submission": (r) => r.status === 422,
        });
      },
    },
    {
      repetitions: 30,
      group: "incorrect VDS",
      function: () => {
        const vdsBody = {
          cp_name: "Mock CP",
          pou: {
            commit_sha1: "9d38fc63bb9ffbc65f976cbca45e096bad3b30e1",
            sanitizer: "id_1",
          },
          pov: {
            harness: "id_1",
            data: "aW5jb3JyZWN0Cg==",
          },
        };
        const vdsSubmissionResp = http.post(
          BASE_URL + "/submission/vds/",
          JSON.stringify(vdsBody),
          headers,
        );

        check(vdsSubmissionResp, {
          "Successful vds submission": (r) =>
            r.status === 200 && r.json("vd_uuid"),
        });

        const vdUuid = vdsSubmissionResp.json("vd_uuid");
        let vdsStatusResp = http.get(
          BASE_URL + `/submission/vds/${vdUuid}`,
          headers,
        );

        console.log(
          `VDS status resp before first pending check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
        );
        check(vdsStatusResp, {
          "Successful submission pending status check": (r) =>
            r.status === 200 && r.json("status") === "pending",
        });

        console.log("Waiting for VDS test to complete");
        console.log(`Status is ${vdsStatusResp.json("status")}`);
        while (vdsStatusResp.json("status") === "pending") {
          sleep(5);
          vdsStatusResp = http.get(
            BASE_URL + `/submission/vds/${vdUuid}`,
            headers,
          );
          console.log(
            `VDS status resp before pending check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
          );
          check(vdsStatusResp, {
            "VDS status check response 200": (r) => r.status === 200,
          });
          console.log(`Status is ${vdsStatusResp.json("status")}`);
        }

        console.log(
          `VDS status resp before rejected check: ${vdsStatusResp.status} ${JSON.stringify(vdsStatusResp.json())}`,
        );
        check(vdsStatusResp, {
          "Successful VDS submission rejected status check": (r) =>
            r.status === 200 && r.json("status") === "rejected",
        });
      },
    },
  ];

  while (functions.length > 0) {
    const index = Math.floor(Math.random() * functions.length);
    const func = functions[index];
    group(func.group, func.function);
    func.repetitions -= 1;
    console.log(
      `After this run, ${func.group} has ${func.repetitions} repetitions left`,
    );
    if (func.repetitions <= 0) {
      functions = functions.splice(index, 1);
    }
  }
}
