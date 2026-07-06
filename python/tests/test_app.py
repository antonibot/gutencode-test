"""The API conformance suite — the SAME cases run in go (app_test.go) and node (test/app.test.js).
Cases are grouped per domain (parametrized) so a failure names the domain: test_domain[<domain>]."""
import json
import os
import sys

os.environ.setdefault("APP_TEST_CLOCK", "1")   # the test-clock seam: `now` params are honored only under this
os.environ.setdefault("APP_TEST_SESSIONS", "1")  # the test-session seam: `test:<subject>` tokens resolve only under this
os.environ.setdefault("LOG_LEVEL", "silent")   # quiet access logs during the suite
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import warnings                                 # noqa: E402

# starlette warns (httpx vs the newer httpx2) the moment `starlette.testclient` is IMPORTED — so the filter must be
# registered BEFORE that import to take effect. A library-internal note, not anything this app does; keeps output clean.
warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")

import pytest                                   # noqa: E402
from starlette.testclient import TestClient     # noqa: E402

from app_pkg.app import app                     # noqa: E402

GROUPS = json.loads(r"""
[
 {
  "domain": "admin",
  "cases": [
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "deactivate_user",
     "target": "alice"
    },
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "action": "deactivate_user",
     "target": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "archive_org",
     "target": "acme"
    },
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "action": "archive_org",
     "target": "acme"
    }
   },
   {
    "method": "GET",
    "path": "/admin/actions",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "action": "deactivate_user",
       "target": "alice"
      },
      {
       "id": 2,
       "action": "archive_org",
       "target": "acme"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/admin/actions?limit=1",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "action": "deactivate_user",
       "target": "alice"
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/admin/actions?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 2,
       "action": "archive_org",
       "target": "acme"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/admin/actions?cursor=!!!",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/admin/actions?limit=0",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/admin/actions?limit=1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/admin/actions/1",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "action": "deactivate_user",
     "target": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "x",
     "target": "y"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "x",
     "target": "y"
    },
    "headers": {
     "Authorization": "Bearer wrong-token"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "x",
     "target": "y"
    },
    "headers": {
     "Authorization": "admin_dev_token_change_me"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/admin/actions",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/admin/actions/1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/admin/actions/999",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/admin/actions/abc",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/admin/actions/5.0",
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "target": "y"
    },
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "",
     "target": "y"
    },
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/admin/actions",
    "json": {
     "action": "x",
     "target": 7
    },
    "headers": {
     "Authorization": "Bearer admin_dev_token_change_me"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "agent",
  "cases": [
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper",
     "system_prompt": "be helpful"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "name": "helper",
     "system_prompt": "be helpful"
    }
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": 7,
     "system_prompt": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "agent_id": 1
    }
   },
   {
    "method": "POST",
    "path": "/agents/999/sessions",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "use calc 2+2"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "session_id": 1,
     "output": "answer: 4.0",
     "iterations": 2,
     "terminated": false
    }
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "use calc 2+2*3"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "output": "answer: 8.0"
    }
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "use nope x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "output": "answer: error: tool 'nope' not found",
     "terminated": false
    }
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "hello"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "output": "[fake] hello",
     "iterations": 1
    }
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "use forever x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "iterations": 6,
     "terminated": true,
     "output": "stopped: max iterations reached"
    }
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/999/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/agents/1/sessions/1/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200
   },
   {
    "method": "GET",
    "path": "/agents/1/sessions/999/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/agents/1/sessions/1/messages",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/agents/1/sessions/1/messages",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/agents/999/sessions/1/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper",
     "system_prompt": "be helpful"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper",
     "system_prompt": "be helpful"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper",
     "system_prompt": "be helpful"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/",
    "json": {
     "name": "helper"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "hello"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "hello"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {
     "input": "hello"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/agents/1/sessions/1/run",
    "json": {},
    "status": 401
   }
  ]
 },
 {
  "domain": "ai_memory",
  "cases": [
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "hello world",
     "scope": "work"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "work",
     "created_at": 1000
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "a plain note"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "default",
     "created_at": 1000
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "temp fact",
     "scope": "ttl",
     "ttl_seconds": 100
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "ttl",
     "created_at": 1000,
     "expires_at": 1100
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "rich",
     "scope": "r",
     "importance": 5,
     "tags": [
      "a",
      "b"
     ],
     "metadata": {
      "k": "v"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "r",
     "created_at": 1000
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "forge",
     "scope": "drv",
     "ttl_seconds": 100,
     "expires_at": 9999999999
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "drv",
     "expires_at": 1100
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "farfuture",
     "scope": "clamp",
     "ttl_seconds": 9007199254740991
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "clamp",
     "expires_at": 9007199254740991
    }
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=nonesuch",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=ttl&now=1101",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=work",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "to be forgotten",
     "scope": "del"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "del"
    }
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories?scope=del",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=del",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories?scope=",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories/1.0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories/9%1F9",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "scope": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "ttl_seconds": 1.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "ttl_seconds": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "ttl_seconds": -5
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "ttl_seconds": 9007199254740993
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "importance": -1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "importance": 2.5
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "impzero",
     "scope": "impz",
     "importance": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "impz"
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "metadata": {
      "k": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "metadata": {
      "k": {}
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "tags": [
      5
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "scope": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "n1",
     "scope": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "default"
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "n2",
     "scope": "nulls",
     "importance": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "nulls"
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "n3",
     "scope": "nulls",
     "ttl_seconds": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "nulls"
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "metadata": {
      "k": null
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x",
     "tags": [
      null
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=work&limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=work&limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=work&cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories?now=1000",
    "json": {
     "content": "mine",
     "scope": "mass",
     "owner": "bob",
     "id": 4242
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "scope": "mass"
    }
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=mass",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ai_memory/memories",
    "json": {
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories?scope=work",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ai_memory/memories/1",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories/1",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/ai_memory/memories?scope=work",
    "status": 401
   }
  ]
 },
 {
  "domain": "ai_provider",
  "cases": [
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "hello"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "model": "fake",
     "output": "[fake] HELLO",
     "cached": false,
     "usage": {
      "prompt_tokens": 5,
      "completion_tokens": 12,
      "cost": 0
     }
    }
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "hello"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "model": "fake",
     "output": "[fake] HELLO",
     "cached": true,
     "usage": {
      "prompt_tokens": 5,
      "completion_tokens": 12,
      "cost": 0
     }
    }
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "requests": 1,
     "prompt_tokens": 5,
     "completion_tokens": 12,
     "cost": 0
    }
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "ship it",
     "model": "smart"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "model": "smart",
     "output": "[smart] SHIP IT",
     "cached": false,
     "usage": {
      "prompt_tokens": 7,
      "completion_tokens": 15,
      "cost": 0
     }
    }
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "ship it",
     "model": "gpt-99"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "model": "fake",
     "cached": false,
     "usage": {
      "prompt_tokens": 7,
      "completion_tokens": 14,
      "cost": 0
     }
    }
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "requests": 3,
     "prompt_tokens": 19,
     "completion_tokens": 41,
     "cost": 0
    }
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "headers": {
     "Authorization": "test:root"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ai/usage",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "x",
     "model": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "hello"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "hello"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": "hello"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ai/complete",
    "json": {
     "prompt": ""
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "ai_tools",
  "cases": [
   {
    "method": "GET",
    "path": "/tools",
    "status": 200
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": "hello"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "upper",
     "ok": true,
     "output": "HELLO"
    }
   },
   {
    "method": "POST",
    "path": "/tools/reverse/invoke",
    "json": {
     "args": {
      "text": "abc"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "reverse",
     "ok": true,
     "output": "cba"
    }
   },
   {
    "method": "POST",
    "path": "/tools/wordcount/invoke",
    "json": {
     "args": {
      "text": "the quick brown fox"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "wordcount",
     "ok": true,
     "output": "4"
    }
   },
   {
    "method": "POST",
    "path": "/tools/repeat/invoke",
    "json": {
     "args": {
      "text": "ab",
      "n": 3
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "repeat",
     "ok": true,
     "output": "ababab"
    }
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {}
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "upper",
     "ok": false,
     "error": "missing required arg 'text'"
    }
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "upper",
     "ok": false,
     "error": "missing required arg 'text'"
    }
   },
   {
    "method": "POST",
    "path": "/tools/repeat/invoke",
    "json": {
     "args": {
      "text": "ab",
      "n": 5.0
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "repeat",
     "ok": false,
     "error": "arg 'n' must be an integer"
    }
   },
   {
    "method": "POST",
    "path": "/tools/repeat/invoke",
    "json": {
     "args": {
      "text": "ab",
      "n": "5"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "repeat",
     "ok": false,
     "error": "arg 'n' must be an integer"
    }
   },
   {
    "method": "POST",
    "path": "/tools/repeat/invoke",
    "json": {
     "args": {
      "text": "ab",
      "n": true
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "repeat",
     "ok": false,
     "error": "arg 'n' must be an integer"
    }
   },
   {
    "method": "POST",
    "path": "/tools/repeat/invoke",
    "json": {
     "args": {
      "text": "ab",
      "n": 99999999999999999999
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "repeat",
     "ok": false,
     "error": "arg 'n' must be an integer"
    }
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": 123
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "upper",
     "ok": false,
     "error": "arg 'text' must be a string"
    }
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": "hi",
      "extra": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "tool": "upper",
     "ok": true,
     "output": "HI"
    }
   },
   {
    "method": "POST",
    "path": "/tools/launch_missiles/invoke",
    "json": {
     "args": {}
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/tools/__proto__/invoke",
    "json": {
     "args": {
      "text": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/tools/p%1Fq/invoke",
    "json": {
     "args": {}
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": "not-an-object"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": [
      1,
      2
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": "hello"
     }
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": "hello"
     }
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": {
      "text": "hello"
     }
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/tools/upper/invoke",
    "json": {
     "args": "not-an-object"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "ai_workflow",
  "cases": [
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      {
       "op": "append",
       "text": " world"
      },
      {
       "op": "prepend",
       "text": ">> "
      },
      {
       "op": "length"
      }
     ]
    },
    "status": 201,
    "expect": {
     "id": 1,
     "steps": 3
    }
   },
   {
    "method": "POST",
    "path": "/workflows/1/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": "hello"
    },
    "status": 200,
    "expect": {
     "output": "14",
     "steps_run": 3,
     "ok": true,
     "trace": [
      {
       "op": "append",
       "output": "hello world"
      },
      {
       "op": "prepend",
       "output": ">> hello world"
      },
      {
       "op": "length",
       "output": "14"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      {
       "op": "truncate",
       "n": 3
      }
     ]
    },
    "status": 201,
    "expect": {
     "id": 2,
     "steps": 1
    }
   },
   {
    "method": "POST",
    "path": "/workflows/2/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": "hello"
    },
    "status": 200,
    "expect": {
     "output": "hel",
     "steps_run": 1,
     "ok": true
    }
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      {
       "op": "not-a-real-op"
      }
     ]
    },
    "status": 201,
    "expect": {
     "id": 3,
     "steps": 1
    }
   },
   {
    "method": "POST",
    "path": "/workflows/3/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": "abc"
    },
    "status": 200,
    "expect": {
     "output": "abc",
     "steps_run": 0,
     "ok": false
    }
   },
   {
    "method": "POST",
    "path": "/workflows/999999/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": "x"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/workflows/abc/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": "x"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": []
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": "nope"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      {
       "text": "no op"
      }
     ]
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      {
       "op": 7
      }
     ]
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "steps": [
      null
     ]
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows/1/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {},
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows/1/run",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "json": {
     "input": 7
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/workflows",
    "json": {
     "steps": [
      {
       "op": "length"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/workflows/1/run",
    "json": {
     "input": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "json": {
     "steps": [
      {
       "op": "length"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/workflows",
    "headers": {
     "Authorization": "test:u1"
    },
    "json": {
     "steps": [
      {
       "op": "length"
      }
     ]
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "api_keys",
  "cases": [
   {
    "method": "POST",
    "path": "/api_keys?now=1700000000",
    "json": {
     "name": "ci",
     "scopes": [
      "read",
      "write"
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "name": "ci",
     "scopes": [
      "read",
      "write"
     ],
     "status": "active",
     "created_at": 1700000000
    }
   },
   {
    "method": "POST",
    "path": "/api_keys?now=1700000001",
    "json": {
     "name": "deploy",
     "scopes": [
      "read"
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "name": "deploy",
     "scopes": [
      "read"
     ],
     "status": "active",
     "created_at": 1700000001
    }
   },
   {
    "method": "GET",
    "path": "/api_keys/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "name": "ci",
     "scopes": [
      "read",
      "write"
     ],
     "prefix": "ak_1",
     "status": "active",
     "created_at": 1700000000
    }
   },
   {
    "method": "GET",
    "path": "/api_keys",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "name": "ci",
       "scopes": [
        "read",
        "write"
       ],
       "prefix": "ak_1",
       "status": "active",
       "created_at": 1700000000
      },
      {
       "id": 2,
       "name": "deploy",
       "scopes": [
        "read"
       ],
       "prefix": "ak_2",
       "status": "active",
       "created_at": 1700000001
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/api_keys?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "name": "ci",
       "scopes": [
        "read",
        "write"
       ],
       "prefix": "ak_1",
       "status": "active",
       "created_at": 1700000000
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/api_keys?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 2,
       "name": "deploy",
       "scopes": [
        "read"
       ],
       "prefix": "ak_2",
       "status": "active",
       "created_at": 1700000001
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/api_keys",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/api_keys",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/api_keys?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/api_keys?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/api_keys?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/api_keys?limit=1&limit=2",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys/verify",
    "json": {
     "key": "ak_nope_wrong"
    },
    "status": 200,
    "expect": {
     "valid": false,
     "scopes": []
    }
   },
   {
    "method": "POST",
    "path": "/api_keys/verify",
    "json": {
     "key": "garbage"
    },
    "status": 200,
    "expect": {
     "valid": false,
     "scopes": []
    }
   },
   {
    "method": "GET",
    "path": "/api_keys/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/api_keys/1/rotate",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/api_keys/1/revoke",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/api_keys/1/revoke",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "status": "revoked"
    }
   },
   {
    "method": "POST",
    "path": "/api_keys/1/revoke",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "status": "revoked"
    }
   },
   {
    "method": "GET",
    "path": "/api_keys/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/api_keys/999999/rotate",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/api_keys/999999/revoke",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/api_keys/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x",
     "scopes": [
      "read"
     ]
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/api_keys/1",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys/1/rotate",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys/1/revoke",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x",
     "scopes": [
      "read"
     ]
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/api_keys/1",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys/1/rotate",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys/1/revoke",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "scopes": [
      "read"
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "",
     "scopes": [
      "read"
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x",
     "scopes": "read"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x",
     "scopes": [
      7
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys",
    "json": {
     "name": "x",
     "scopes": [
      ""
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys/verify",
    "json": {},
    "status": 422
   },
   {
    "method": "POST",
    "path": "/api_keys/verify",
    "json": {
     "key": ""
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "audit_log",
  "cases": [
   {
    "method": "POST",
    "path": "/audit_log/events?now=1700000000",
    "json": {
     "actor": "alice",
     "action": "user_login"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "at": 1700000000,
     "actor": "alice",
     "action": "user_login",
     "prev": "GENESIS",
     "hash": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46"
    }
   },
   {
    "method": "POST",
    "path": "/audit_log/events?now=1700000001",
    "json": {
     "actor": "user:42",
     "action": "doc_deleted"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "at": 1700000001,
     "actor": "user:42",
     "action": "doc_deleted",
     "prev": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46",
     "hash": "1f3c29d837e1323f62937b6e018cf192c7936db6f6a9267c162b3e3b92c10013"
    }
   },
   {
    "method": "GET",
    "path": "/audit_log/verify",
    "status": 200,
    "expect": {
     "valid": true,
     "count": 2
    }
   },
   {
    "method": "GET",
    "path": "/audit_log/events",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "at": 1700000000,
       "actor": "alice",
       "action": "user_login",
       "prev": "GENESIS",
       "hash": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46"
      },
      {
       "id": 2,
       "at": 1700000001,
       "actor": "user:42",
       "action": "doc_deleted",
       "prev": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46",
       "hash": "1f3c29d837e1323f62937b6e018cf192c7936db6f6a9267c162b3e3b92c10013"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/audit_log/events?limit=1",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "at": 1700000000,
       "actor": "alice",
       "action": "user_login",
       "prev": "GENESIS",
       "hash": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46"
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/audit_log/events?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 2,
       "at": 1700000001,
       "actor": "user:42",
       "action": "doc_deleted",
       "prev": "d14a8442973b6871f410c0fe2570751de075378791f87d3aa334a2a713371f46",
       "hash": "1f3c29d837e1323f62937b6e018cf192c7936db6f6a9267c162b3e3b92c10013"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/audit_log/events?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/audit_log/events?limit=0",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/audit_log/events?limit=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {},
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": 7
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": ""
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": true
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "action": "no_actor"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": 7,
     "action": "bad_actor_type"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "",
     "action": "empty_actor"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": "anon_append"
    },
    "status": 401,
    "headers": {}
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": "alice_append"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": "bad_token_append"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "action": ""
    },
    "status": 401,
    "headers": {}
   },
   {
    "method": "GET",
    "path": "/audit_log/events",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/audit_log/events",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/audit_log/events",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/audit_log/verify",
    "status": 200,
    "expect": {
     "valid": true
    }
   },
   {
    "method": "POST",
    "path": "/audit_log/events",
    "json": {
     "actor": "alice",
     "action": "admin_is_not_a_service"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "auth",
  "cases": [
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "alice@ex.com",
     "password": "correct horse"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "alice@ex.com",
     "password": "a different password"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/login",
    "json": {
     "email": "alice@ex.com",
     "password": "correct horse"
    },
    "status": 200,
    "expect": {
     "token_type": "bearer"
    }
   },
   {
    "method": "POST",
    "path": "/auth/login",
    "json": {
     "email": "alice@ex.com",
     "password": "the WRONG password"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/auth/login",
    "json": {
     "email": "ghost@ex.com",
     "password": "no such account"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/auth/me",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/auth/me",
    "headers": {
     "Authorization": "Bearer not-a-real-token"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/auth/me",
    "headers": {
     "Authorization": "garbage-no-scheme"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/auth/me",
    "headers": {
     "Authorization": "Bearer test:alice@ex.com"
    },
    "status": 200,
    "expect": {
     "email": "alice@ex.com",
     "id": "alice@ex.com"
    }
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "bob@ex.com"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "bob@ex.com",
     "password": "short"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "bob@ex.com",
     "password": "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "edge@ex.com",
     "password": "12345678"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": 7,
     "password": "valid password"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "",
     "password": "valid password"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "num@ex.com",
     "password": 123
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "bob@ex.com",
     "password": true
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/login",
    "json": {
     "email": "alice@ex.com"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/refresh",
    "json": {
     "token": "nope.nottoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/auth/refresh",
    "json": {},
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/logout",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/auth/logout",
    "headers": {
     "Authorization": "Bearer test:alice@ex.com"
    },
    "status": 200,
    "expect": {
     "message": "logged out"
    }
   },
   {
    "method": "POST",
    "path": "/auth/password/reset/request",
    "json": {
     "email": "alice@ex.com"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/password/reset/request",
    "json": {
     "email": "ghost@ex.com"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/password/reset/confirm",
    "json": {
     "token": "bad.token",
     "password": "a new good password"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/auth/password/reset/confirm",
    "json": {
     "token": "bad.token",
     "password": "short"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/auth/verify/request",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/auth/verify/request",
    "headers": {
     "Authorization": "Bearer test:alice@ex.com"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/verify/confirm",
    "json": {
     "token": "bad.token"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/auth/register",
    "json": {
     "email": "\u00fc\u00f1\u00ed-\u4e2d\u6587-\ud83d\udd11@ex.com",
     "password": "p\u00e4ssw\u00f6rd with sp\u00e4ces and \u4e2d\u6587 \ud83d\udd11 that is quite long indeed ok"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/auth/login",
    "json": {
     "email": "\u00fc\u00f1\u00ed-\u4e2d\u6587-\ud83d\udd11@ex.com",
     "password": "p\u00e4ssw\u00f6rd with sp\u00e4ces and \u4e2d\u6587 \ud83d\udd11 that is quite long indeed ok"
    },
    "status": 200,
    "expect": {
     "token_type": "bearer"
    }
   }
  ]
 },
 {
  "domain": "billing",
  "cases": [
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": "pro"
    },
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "owner": "c1",
     "plan": "pro",
     "status": "active",
     "amount": 2000
    }
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": "enterprise"
    },
    "headers": {
     "Authorization": "Bearer test:c2"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "owner": "c2",
     "amount": 10000
    }
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": "free",
     "amount": 999999
    },
    "headers": {
     "Authorization": "Bearer test:c3"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "owner": "c3",
     "amount": 0
    }
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "owner": "c1",
     "plan": "pro",
     "status": "active",
     "amount": 2000
    }
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "headers": {
     "Authorization": "Bearer test:c2"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions/2/cancel",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions/1/cancel",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "status": "canceled",
     "amount": 2000
    }
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions/1/cancel",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "status": "canceled"
    }
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 200,
    "expect": {
     "status": "canceled",
     "amount": 2000
    }
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": "pro"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions/1/cancel",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/1",
    "headers": {
     "Authorization": "test:c1"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": "platinum"
    },
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions",
    "json": {
     "plan": true
    },
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/999999",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/billing/subscriptions/999999/cancel",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/abc",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/billing/subscriptions/5.0",
    "headers": {
     "Authorization": "Bearer test:c1"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "chat_threads",
  "cases": [
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": "Support chat"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "title": "Support chat",
     "metadata": {},
     "created_at": 1000,
     "updated_at": 1000,
     "last_seq": 0
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "title": "",
     "metadata": {},
     "last_seq": 0
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": null,
     "metadata": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "title": "",
     "metadata": {}
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": "Billing chat",
     "metadata": {
      "model": "gpt-4o",
      "topic": "billing"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 4,
     "title": "Billing chat",
     "metadata": {
      "model": "gpt-4o",
      "topic": "billing"
     }
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 5,
     "title": ""
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": "a\u001fb"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": "TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "k": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "k": {}
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "k": null
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": "notobject"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "k01": "v",
      "k02": "v",
      "k03": "v",
      "k04": "v",
      "k05": "v",
      "k06": "v",
      "k07": "v",
      "k08": "v",
      "k09": "v",
      "k10": "v",
      "k11": "v",
      "k12": "v",
      "k13": "v",
      "k14": "v",
      "k15": "v",
      "k16": "v",
      "k17": "v"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk": "v"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "metadata": {
      "k": "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads?now=1000",
    "json": {
     "title": "mine",
     "owner": "bob",
     "id": 4242,
     "last_seq": 99,
     "created_at": 7,
     "updated_at": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 6,
     "title": "mine",
     "last_seq": 0,
     "created_at": 1000,
     "updated_at": 1000
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/6",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1010",
    "json": {
     "role": "user",
     "content": "Hi, my invoice looks wrong"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "seq": 1,
     "thread_id": 1,
     "role": "user",
     "content": "Hi, my invoice looks wrong",
     "metadata": {},
     "created_at": 1010
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1020",
    "json": {
     "role": "assistant",
     "content": "Let me check that for you.",
     "metadata": {
      "model": "gpt-4o"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "seq": 2,
     "role": "assistant",
     "metadata": {
      "model": "gpt-4o"
     },
     "created_at": 1020
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1030",
    "json": {
     "role": "system",
     "content": "escalated to a billing specialist"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "seq": 3,
     "role": "system"
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1040",
    "json": {
     "role": "tool",
     "content": "lookup_invoice inv_42 status=overdue"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "seq": 4,
     "role": "tool"
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "last_seq": 4,
     "created_at": 1000,
     "updated_at": 1040
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1050",
    "json": {
     "role": "user",
     "content": "also, can you resend it?",
     "seq": 999,
     "owner": "bob",
     "thread_id": 77,
     "created_at": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "seq": 5,
     "thread_id": 1,
     "created_at": 1050
    }
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "critic",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "User",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": null,
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": 7,
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user",
     "content": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user",
     "content": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user",
     "content": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user",
     "content": "x",
     "metadata": {
      "k": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/chat_threads/999999/messages?now=1060",
    "json": {
     "role": "user",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=1060",
    "json": {
     "role": "user",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "seq": 1,
       "thread_id": 1,
       "role": "user",
       "content": "Hi, my invoice looks wrong",
       "metadata": {},
       "created_at": 1010
      },
      {
       "seq": 2,
       "thread_id": 1,
       "role": "assistant",
       "content": "Let me check that for you.",
       "metadata": {
        "model": "gpt-4o"
       },
       "created_at": 1020
      },
      {
       "seq": 3,
       "thread_id": 1,
       "role": "system",
       "content": "escalated to a billing specialist",
       "metadata": {},
       "created_at": 1030
      },
      {
       "seq": 4,
       "thread_id": 1,
       "role": "tool",
       "content": "lookup_invoice inv_42 status=overdue",
       "metadata": {},
       "created_at": 1040
      },
      {
       "seq": 5,
       "thread_id": 1,
       "role": "user",
       "content": "also, can you resend it?",
       "metadata": {},
       "created_at": 1050
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?limit=2",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "seq": 1,
       "thread_id": 1,
       "role": "user",
       "content": "Hi, my invoice looks wrong",
       "metadata": {},
       "created_at": 1010
      },
      {
       "seq": 2,
       "thread_id": 1,
       "role": "assistant",
       "content": "Let me check that for you.",
       "metadata": {
        "model": "gpt-4o"
       },
       "created_at": 1020
      }
     ],
     "next_cursor": "Mg"
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?limit=2&cursor=Mg",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "seq": 3,
       "thread_id": 1,
       "role": "system",
       "content": "escalated to a billing specialist",
       "metadata": {},
       "created_at": 1030
      },
      {
       "seq": 4,
       "thread_id": 1,
       "role": "tool",
       "content": "lookup_invoice inv_42 status=overdue",
       "metadata": {},
       "created_at": 1040
      }
     ],
     "next_cursor": "NA"
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?limit=2&cursor=NA",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "seq": 5,
       "thread_id": 1,
       "role": "user",
       "content": "also, can you resend it?",
       "metadata": {},
       "created_at": 1050
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/999999/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/abc/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads?limit=3",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "title": "Support chat",
       "metadata": {},
       "created_at": 1000,
       "updated_at": 1050,
       "last_seq": 5
      },
      {
       "id": 6,
       "title": "mine",
       "metadata": {},
       "created_at": 1000,
       "updated_at": 1000,
       "last_seq": 0
      },
      {
       "id": 5,
       "title": "",
       "metadata": {},
       "created_at": 1000,
       "updated_at": 1000,
       "last_seq": 0
      }
     ],
     "next_cursor": "Mw"
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads?limit=3&cursor=Mw",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 4,
       "title": "Billing chat",
       "metadata": {
        "model": "gpt-4o",
        "topic": "billing"
       },
       "created_at": 1000,
       "updated_at": 1000,
       "last_seq": 0
      },
      {
       "id": 3,
       "title": "",
       "metadata": {},
       "created_at": 1000,
       "updated_at": 1000,
       "last_seq": 0
      },
      {
       "id": 2,
       "title": "",
       "metadata": {},
       "created_at": 1000,
       "updated_at": 1000,
       "last_seq": 0
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/chat_threads?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/1.0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/chat_threads/9%1F9",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2000",
    "json": {
     "title": "Renamed"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 2,
     "title": "Renamed",
     "created_at": 1000,
     "updated_at": 2000,
     "last_seq": 0
    }
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2001",
    "json": {
     "metadata": {
      "pinned": "yes"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "title": "Renamed",
     "metadata": {
      "pinned": "yes"
     },
     "updated_at": 2001
    }
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2002",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2002",
    "json": {
     "title": null
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2002",
    "json": {
     "title": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2002",
    "json": {
     "title": "x",
     "metadata": {
      "k": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/1?now=2003",
    "json": {
     "title": "pwn"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/999999?now=2003",
    "json": {
     "title": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/2?now=2004",
    "json": {
     "title": "Kept",
     "owner": "bob",
     "last_seq": 42,
     "id": 9
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 2,
     "title": "Kept",
     "last_seq": 0
    }
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/5",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/chat_threads/5",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/5/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/5",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/5?now=2005",
    "json": {
     "title": "back"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages?now=2006",
    "json": {
     "role": "user",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/chat_threads",
    "json": {
     "title": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/chat_threads",
    "json": {
     "title": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads/1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/1",
    "json": {
     "title": "x"
    },
    "status": 401
   },
   {
    "method": "PATCH",
    "path": "/chat_threads/1",
    "json": {
     "title": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/1",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/chat_threads/1",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages",
    "json": {
     "role": "user",
     "content": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/chat_threads/1/messages",
    "json": {
     "role": "user",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/chat_threads/1/messages",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "crew",
  "cases": [
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "writer",
       "next": "editor"
      },
      {
       "name": "editor"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "roles": 2
    }
   },
   {
    "method": "POST",
    "path": "/crews/1/run",
    "json": {
     "input": "draft"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "output": "draft [writer] [editor]",
     "handoffs": 2,
     "terminated": true,
     "trace": [
      {
       "role": "writer",
       "output": "draft [writer]"
      },
      {
       "role": "editor",
       "output": "draft [writer] [editor]"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "ping",
       "next": "pong"
      },
      {
       "name": "pong",
       "next": "ping"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "roles": 2
    }
   },
   {
    "method": "POST",
    "path": "/crews/2/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "handoffs": 25,
     "terminated": false
    }
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "solo",
       "next": "ghost"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "roles": 1
    }
   },
   {
    "method": "POST",
    "path": "/crews/3/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "output": "x [solo]",
     "handoffs": 1,
     "terminated": false,
     "trace": [
      {
       "role": "solo",
       "output": "x [solo]"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/crews/2/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u2"
    },
    "status": 200,
    "expect": {
     "handoffs": 25,
     "terminated": false
    }
   },
   {
    "method": "POST",
    "path": "/crews/999999/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/crews/abc/run",
    "json": {
     "input": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": []
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": "nope"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "next": "b"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": 7
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "a"
      },
      {
       "name": "a"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      null
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "a",
       "next": 7
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews/1/run",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews/1/run",
    "json": {
     "input": 7
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/crews",
    "json": {
     "roles": [
      {
       "name": "writer",
       "next": "editor"
      },
      {
       "name": "editor"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/crews/1/run",
    "json": {
     "input": "draft"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/crews/1/run",
    "json": {
     "input": "draft"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "email_outbox",
  "cases": [
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi",
     "text": "body"
    },
    "headers": {
     "Idempotency-Key": "k1",
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi"
    }
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi",
     "text": "body"
    },
    "headers": {
     "Idempotency-Key": "k1",
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 1
    }
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Changed",
     "text": "body"
    },
    "headers": {
     "Idempotency-Key": "k1",
     "Authorization": "Bearer test:root"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "bcc": [
      "b@x.com"
     ],
     "subject": "Hi",
     "text": "body"
    },
    "headers": {
     "Idempotency-Key": "k1",
     "Authorization": "Bearer test:root"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "No key",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 2
    }
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "template": {
      "id": "verify_email",
      "data": {
       "name": "Alice",
       "link": "https://x.com/v/abc"
      }
     }
    },
    "headers": {
     "Idempotency-Key": "k2",
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "subject": "Verify your email address"
    }
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi\r\nBcc: evil@x.com",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi\nthere",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi\rthere",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi\u2028there",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "Hi\u0085there",
     "text": "body"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "template": {
      "id": "notify",
      "data": {
       "title": "X\r\nBcc: evil@x.com",
       "body": "hi"
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "noatsign",
     "to": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@b@c.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@localhost"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a b@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "cc": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "to": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "s"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b",
     "template": {
      "id": "verify_email",
      "data": {
       "name": "A",
       "link": "l"
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      7
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": true,
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "template": {
      "id": "ghost",
      "data": {}
     }
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "template": {
      "id": "notify",
      "data": {
       "body": "b"
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "template": {
      "id": "notify",
      "data": {
       "title": 7,
       "body": "b"
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "alice@x.com",
     "to": [
      "c@x.com"
     ],
     "subject": "Alice mail",
     "text": "hi"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 4,
     "from": "alice@x.com"
    }
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages?limit=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages/1",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "from": "s@x.com",
     "subject": "Hi"
    }
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages/999999",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages/abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/email_outbox/messages",
    "json": {
     "from": "s@x.com",
     "to": [
      "a@x.com"
     ],
     "subject": "s",
     "text": "b"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/email_outbox/messages/1",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "evals",
  "cases": [
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "greet",
     "cases": [
      {
       "id": "c_exact",
       "scorer": "exact",
       "expected": "hello"
      },
      {
       "id": "c_contains",
       "scorer": "contains",
       "expected": "lo wor"
      },
      {
       "id": "c_starts",
       "scorer": "starts_with",
       "expected": "hel"
      },
      {
       "id": "c_ends",
       "scorer": "ends_with",
       "expected": "rld"
      },
      {
       "id": "c_iexact",
       "scorer": "iexact",
       "expected": "HELLO"
      },
      {
       "id": "c_icontains",
       "scorer": "icontains",
       "expected": "WORLD"
      },
      {
       "id": "c_int",
       "scorer": "equals_int",
       "expected": "42"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "greet",
     "owner": "alice",
     "case_count": 7,
     "created_at": 1700000000
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites/greet",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "greet",
     "owner": "alice",
     "case_count": 7,
     "created_at": 1700000000,
     "cases": [
      {
       "id": "c_contains",
       "scorer": "contains",
       "expected": "lo wor"
      },
      {
       "id": "c_ends",
       "scorer": "ends_with",
       "expected": "rld"
      },
      {
       "id": "c_exact",
       "scorer": "exact",
       "expected": "hello"
      },
      {
       "id": "c_icontains",
       "scorer": "icontains",
       "expected": "WORLD"
      },
      {
       "id": "c_iexact",
       "scorer": "iexact",
       "expected": "HELLO"
      },
      {
       "id": "c_int",
       "scorer": "equals_int",
       "expected": "42"
      },
      {
       "id": "c_starts",
       "scorer": "starts_with",
       "expected": "hel"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {
      "c_exact": "hello",
      "c_contains": "hello world",
      "c_starts": "hello",
      "c_ends": "hello world",
      "c_iexact": "hello",
      "c_icontains": "hello world",
      "c_int": "42"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 7,
     "total": 7,
     "all_pass": true,
     "results": [
      {
       "case_id": "c_contains",
       "pass": true
      },
      {
       "case_id": "c_ends",
       "pass": true
      },
      {
       "case_id": "c_exact",
       "pass": true
      },
      {
       "case_id": "c_icontains",
       "pass": true
      },
      {
       "case_id": "c_iexact",
       "pass": true
      },
      {
       "case_id": "c_int",
       "pass": true
      },
      {
       "case_id": "c_starts",
       "pass": true
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {
      "c_exact": "HELLO",
      "c_contains": "nope",
      "c_starts": "goodbye",
      "c_ends": "nope",
      "c_iexact": "HeLLo",
      "c_icontains": "no match",
      "c_int": "43"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 1,
     "total": 7,
     "all_pass": false,
     "results": [
      {
       "case_id": "c_contains",
       "pass": false
      },
      {
       "case_id": "c_ends",
       "pass": false
      },
      {
       "case_id": "c_exact",
       "pass": false
      },
      {
       "case_id": "c_icontains",
       "pass": false
      },
      {
       "case_id": "c_iexact",
       "pass": true
      },
      {
       "case_id": "c_int",
       "pass": false
      },
      {
       "case_id": "c_starts",
       "pass": false
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "det",
     "cases": [
      {
       "id": "ci",
       "scorer": "iexact",
       "expected": "STRASSE"
      },
      {
       "id": "cn",
       "scorer": "equals_int",
       "expected": "5"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "det",
     "owner": "alice",
     "case_count": 2
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/det/score",
    "json": {
     "outputs": {
      "ci": "strasse",
      "cn": "5"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 2,
     "total": 2,
     "all_pass": true
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/det/score",
    "json": {
     "outputs": {
      "ci": "stra\u00dfe",
      "cn": "5.0"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 0,
     "total": 2,
     "all_pass": false,
     "results": [
      {
       "case_id": "ci",
       "pass": false
      },
      {
       "case_id": "cn",
       "pass": false
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/det/score",
    "json": {
     "outputs": {
      "ci": "strasse",
      "cn": "9007199254740992"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 1,
     "total": 2,
     "all_pass": false,
     "results": [
      {
       "case_id": "ci",
       "pass": true
      },
      {
       "case_id": "cn",
       "pass": false
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "noexec",
     "cases": [
      {
       "id": "cx",
       "scorer": "contains",
       "expected": ".*"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "case_count": 1
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/noexec/score",
    "json": {
     "outputs": {
      "cx": "abc"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 0,
     "total": 1,
     "all_pass": false,
     "results": [
      {
       "case_id": "cx",
       "pass": false
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/noexec/score",
    "json": {
     "outputs": {
      "cx": "a.*b"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "passed": 1,
     "total": 1,
     "all_pass": true
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet",
    "json": {
     "name": "greet",
     "cases": [
      {
       "id": "z",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 405
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700009999",
    "json": {
     "name": "greet",
     "cases": [
      {
       "id": "z",
       "scorer": "exact",
       "expected": "changed"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 409
   },
   {
    "method": "GET",
    "path": "/evals/suites/greet",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "case_count": 7,
     "created_at": 1700000000
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "shared",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "alice-secret"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "shared",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "bob-secret"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "owner": "bob"
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites/shared",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "alice",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "alice-secret"
      }
     ]
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites/shared",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "owner": "bob",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "bob-secret"
      }
     ]
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites/greet",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {
      "c_exact": "hello"
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/evals/suites/nope",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/evals/suites/nope/score",
    "json": {
     "outputs": {
      "x": "y"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/evals/suites",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "aaa",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 201
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000001",
    "json": {
     "name": "bbb",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 201
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000002",
    "json": {
     "name": "ccc",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 201
   },
   {
    "method": "GET",
    "path": "/evals/suites",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "aaa",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000000
      },
      {
       "name": "bbb",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000001
      },
      {
       "name": "ccc",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000002
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites?limit=2",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "aaa",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000000
      },
      {
       "name": "bbb",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000001
      }
     ],
     "next_cursor": "Mg"
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites?limit=2&cursor=Mg",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "ccc",
       "owner": "carol",
       "case_count": 1,
       "created_at": 1700000002
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/evals/suites?limit=0",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/evals/suites?limit=abc",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/evals/suites?limit=2.0",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/evals/suites?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "massassign",
     "owner": "bob",
     "created_at": 999,
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x",
       "owner": "bob"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "massassign",
     "owner": "alice",
     "created_at": 1700000000,
     "case_count": 1
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites?now=1700000000",
    "json": {
     "name": "derivesmug",
     "case_count": 999,
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "case_count": 1
    }
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": []
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": "notalist"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "bad\u001fname",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "regex",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "exact"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": 7
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "dup",
       "scorer": "exact",
       "expected": "x"
      },
      {
       "id": "dup",
       "scorer": "exact",
       "expected": "y"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "equals_int",
       "expected": "5.0"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "equals_int",
       "expected": "99999999999999999999"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "e",
     "cases": [
      {
       "id": "a",
       "scorer": "equals_int",
       "expected": "notanint"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {
      "c_exact": "hello"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": "notamap"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {
      "c_exact": 7,
      "c_contains": "x",
      "c_starts": "x",
      "c_ends": "x",
      "c_iexact": "x",
      "c_icontains": "x",
      "c_int": "1"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "x",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/evals/suites",
    "json": {
     "name": "",
     "cases": [
      {
       "id": "a",
       "scorer": "exact",
       "expected": "x"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/evals/suites",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/evals/suites/greet",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/evals/suites/greet/score",
    "json": {
     "outputs": {}
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/evals/suites",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/evals/suites",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "feature_flags",
  "cases": [
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "dark_mode",
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "key": "dark_mode",
     "rollout": 50
    }
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "dark_mode",
     "rollout": 10
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 409
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode",
    "status": 200,
    "expect": {
     "key": "dark_mode",
     "rollout": 50
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=bob",
    "status": 200,
    "expect": {
     "key": "dark_mode",
     "subject": "bob",
     "enabled": true
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=alice",
    "status": 200,
    "expect": {
     "key": "dark_mode",
     "subject": "alice",
     "enabled": false
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=frank",
    "status": 200,
    "expect": {
     "subject": "frank",
     "enabled": true
    }
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 31
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "key": "dark_mode",
     "rollout": 31
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=bob",
    "status": 200,
    "expect": {
     "enabled": true
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=dave",
    "status": 200,
    "expect": {
     "subject": "dave",
     "enabled": false
    }
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 100
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "rollout": 100
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=alice",
    "status": 200,
    "expect": {
     "enabled": true
    }
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 0
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "rollout": 0
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=frank",
    "status": 200,
    "expect": {
     "enabled": false
    }
   },
   {
    "method": "GET",
    "path": "/feature_flags/ghost",
    "status": 404
   },
   {
    "method": "PUT",
    "path": "/feature_flags/ghost",
    "json": {
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/feature_flags/ghost/evaluate?subject=x",
    "status": 404
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate",
    "status": 422
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=",
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "",
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "x",
     "rollout": 101
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "x",
     "rollout": -1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "x",
     "rollout": 1.5
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "x",
     "rollout": 50.0
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "x",
     "rollout": "half"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 200
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "anon_create",
     "rollout": 50
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "anon_create",
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "anon_create",
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/feature_flags",
    "json": {
     "key": "",
     "rollout": 50
    },
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 50
    },
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 50
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/feature_flags/dark_mode",
    "json": {
     "rollout": 200
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/feature_flags/dark_mode/evaluate?subject=bob",
    "status": 200,
    "expect": {
     "key": "dark_mode",
     "subject": "bob"
    }
   }
  ]
 },
 {
  "domain": "file_store",
  "cases": [
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "hello.txt",
     "content_b64": "aGVsbG8gd29ybGQ="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "key": "hello.txt",
     "provider": "store",
     "size": 11,
     "content_type": "application/octet-stream",
     "created_at": 1000,
     "etag": "dc9c1c09907c36f5379d615ae61c02b46ba254d92edb77cb63bdcc5247ccd01c"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/hello.txt/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "hello.txt",
     "size": 11,
     "content_type": "application/octet-stream",
     "created_at": 1000,
     "etag": "dc9c1c09907c36f5379d615ae61c02b46ba254d92edb77cb63bdcc5247ccd01c"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/hello.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "copy.txt",
     "content_b64": "aGVsbG8gd29ybGQ="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "size": 11,
     "etag": "dc9c1c09907c36f5379d615ae61c02b46ba254d92edb77cb63bdcc5247ccd01c"
    }
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "empty.bin",
     "content_b64": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "size": 0,
     "etag": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "page.html",
     "content_b64": "PGgxPmhpPC9oMT4=",
     "content_type": "text/html"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "size": 11,
     "content_type": "text/html",
     "etag": "0ec07bc87b5053a70c1c13380f99c2b7b491094416f98ddfa6a3f1b68b16b380"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/page.html/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "content_type": "text/html",
     "size": 11,
     "etag": "0ec07bc87b5053a70c1c13380f99c2b7b491094416f98ddfa6a3f1b68b16b380"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/page.html",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/file_store?now=2000",
    "json": {
     "key": "hello.txt",
     "content_b64": "YnJhbmQgbmV3IGJ5dGVz"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "size": 15,
     "created_at": 2000,
     "etag": "bdeaa512d95d990ca032d89af6868d3f85abd0550f7d8f31600bb576e67d8786"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/hello.txt/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "size": 15,
     "created_at": 2000,
     "etag": "bdeaa512d95d990ca032d89af6868d3f85abd0550f7d8f31600bb576e67d8786"
    }
   },
   {
    "method": "GET",
    "path": "/file_store",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "key": "copy.txt",
       "size": 11
      },
      {
       "key": "empty.bin",
       "size": 0
      },
      {
       "key": "hello.txt",
       "size": 15
      },
      {
       "key": "page.html",
       "size": 11
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/file_store?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "key": "copy.txt",
       "size": 11
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/file_store?cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "key": "empty.bin",
       "size": 0
      },
      {
       "key": "hello.txt",
       "size": 15
      },
      {
       "key": "page.html",
       "size": 11
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/file_store?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/file_store?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/file_store?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "\uff61",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:cp"
    },
    "status": 201,
    "expect": {
     "key": "\uff61",
     "size": 1
    }
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "\ud83d\ude00",
     "content_b64": "Yg=="
    },
    "headers": {
     "Authorization": "Bearer test:cp"
    },
    "status": 201,
    "expect": {
     "key": "\ud83d\ude00",
     "size": 1
    }
   },
   {
    "method": "GET",
    "path": "/file_store",
    "headers": {
     "Authorization": "Bearer test:cp"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "key": "\uff61",
       "size": 1
      },
      {
       "key": "\ud83d\ude00",
       "size": 1
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": "@@@@"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": "QQQ"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": "QR=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": "QQ=Q"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": "QQ =="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk",
     "content_b64": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "bk"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": "text/html\r\nX-Evil: 1"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": "text/ html"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": "texthtml"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": "text/html;charset=utf-8"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": "*/*"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "ck",
     "content_b64": "YQ==",
     "content_type": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "a/b",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "a\\b",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": ".",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "..",
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": 7,
     "content_b64": "YQ=="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/file_store/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/file_store/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/file_store",
    "json": {
     "key": "x",
     "content_b64": "YQ=="
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store/hello.txt",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store/hello.txt/meta",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/file_store/hello.txt",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store/p%1Fq",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/file_store",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "shared",
     "content_b64": "YWxpY2UgYnl0ZXM="
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "key": "shared",
     "size": 11,
     "etag": "cceed9ec85d911c1e172a09c54a8ffa0b86a1684bb5d1bd5ad583db6da2724a2"
    }
   },
   {
    "method": "POST",
    "path": "/file_store?now=1000",
    "json": {
     "key": "shared",
     "content_b64": "Ym9iIGJ5dGVz"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "key": "shared",
     "size": 9,
     "etag": "e98bc6977be4299b7894dab26b3cdfbaa120cadf9583dabb5412b4ae237631f6"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/shared/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "size": 11,
     "etag": "cceed9ec85d911c1e172a09c54a8ffa0b86a1684bb5d1bd5ad583db6da2724a2"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/shared/meta",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "size": 9,
     "etag": "e98bc6977be4299b7894dab26b3cdfbaa120cadf9583dabb5412b4ae237631f6"
    }
   },
   {
    "method": "GET",
    "path": "/file_store/shared/meta",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/file_store/shared",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/file_store/shared",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/file_store/nonexistent.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/file_store/nonexistent.txt/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/file_store/nonexistent.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/file_store/shared",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/file_store/shared/meta",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/file_store/shared",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/file_store/shared/meta",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "etag": "cceed9ec85d911c1e172a09c54a8ffa0b86a1684bb5d1bd5ad583db6da2724a2"
    }
   }
  ]
 },
 {
  "domain": "health",
  "cases": [
   {
    "method": "GET",
    "path": "/health",
    "status": 200,
    "expect": {
     "status": "ok"
    }
   }
  ]
 },
 {
  "domain": "idempotency",
  "cases": [
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Idempotency-Key": "K1"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken",
     "Idempotency-Key": "K1"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "amount": 500
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "amount": 500
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 999
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 100
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K2"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "amount": 100
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 50
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "amount": 50
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 50
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 201,
    "expect": {
     "id": 4,
     "amount": 50
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 5
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": ""
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": "x"
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 0
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 5.0
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9f"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": -5
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 1.5
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": true
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K9"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer test:u2",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": 5,
     "amount": 500
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer test:u2",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": 5,
     "amount": 500
    }
   },
   {
    "method": "POST",
    "path": "/idempotency/payments",
    "json": {
     "amount": 500
    },
    "headers": {
     "Authorization": "Bearer test:u1",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "amount": 500
    }
   }
  ]
 },
 {
  "domain": "invitations",
  "cases": [
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "a@example.com"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "email": "a@example.com",
     "inviter": "alice",
     "status": "pending",
     "expires_at": 605800
    }
   },
   {
    "method": "POST",
    "path": "/invitations?now=2000",
    "json": {
     "email": "b@example.com",
     "ttl": 60
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "email": "b@example.com",
     "inviter": "bob",
     "status": "pending",
     "expires_at": 2060
    }
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "c@example.com",
     "inviter": "mallory"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "email": "c@example.com",
     "inviter": "alice",
     "status": "pending",
     "expires_at": 605800
    }
   },
   {
    "method": "POST",
    "path": "/invitations/unknown-token/accept?now=3000",
    "status": 404
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "x@y.com",
     "ttl": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "x@y.com",
     "ttl": 3600.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "x@y.com",
     "ttl": -5
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "x@y.com",
     "ttl": "soon"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations/p%1Fq/accept?now=1000",
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "a@example.com"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "a@example.com"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": "a@example.com"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invitations?now=1000",
    "json": {
     "email": ""
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "invoices",
  "cases": [
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 100,
     "line_items": [
      {
       "description": "widget",
       "quantity": 3,
       "unit_amount": 500
      },
      {
       "description": "setup fee",
       "quantity": 1,
       "unit_amount": 1000
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "status": "draft",
     "customer": "acme",
     "currency": "usd",
     "subtotal": 2500,
     "tax": 100,
     "total": 2600,
     "number": null,
     "amount_paid": 0
    }
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 100,
     "line_items": [
      {
       "description": "widget",
       "quantity": 3,
       "unit_amount": 500
      },
      {
       "description": "setup fee",
       "quantity": 1,
       "unit_amount": 1000
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "status": "draft",
     "subtotal": 2500,
     "total": 2600
    }
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "widget",
       "quantity": 1,
       "unit_amount": 500
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "globex",
     "currency": "eur",
     "tax": 0,
     "line_items": [
      {
       "description": "consult",
       "quantity": 2,
       "unit_amount": 250
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K2"
    },
    "status": 201,
    "expect": {
     "status": "draft",
     "customer": "globex",
     "currency": "eur",
     "subtotal": 500,
     "total": 500
    }
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": ""
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "xyz",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": []
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 0,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 500.0
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 9007199254740992
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 4503599627370496,
       "unit_amount": 4
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/invoices",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/invoices?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/invoices?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/invoices",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/invoices/nope",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/invoices/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/invoices/nope",
    "status": 401
   },
   {
    "method": "PATCH",
    "path": "/invoices/nope",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/invoices/nope",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": []
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/invoices/nope",
    "json": {
     "customer": "acme",
     "currency": "xyz",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/invoices/p%1Fq",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/invoices/nope",
    "json": {
     "customer": "acme",
     "currency": "usd",
     "tax": 0,
     "line_items": [
      {
       "description": "x",
       "quantity": 1,
       "unit_amount": 5
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices/nope/finalize",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/invoices/p%1Fq/finalize",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices/nope/finalize",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices/nope/pay",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/invoices/p%1Fq/pay",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices/nope/pay",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices/nope/void",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/invoices/nope/void",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/invoices/nope/mark_uncollectible",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/invoices/p%1Fq/mark_uncollectible",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/invoices/nope/mark_uncollectible",
    "status": 401
   }
  ]
 },
 {
  "domain": "job_queue",
  "cases": [
   {
    "method": "POST",
    "path": "/job_queue?now=1000",
    "json": {
     "kind": "email",
     "payload": {
      "to": "a@x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "owner": "alice",
     "kind": "email",
     "payload": {
      "to": "a@x"
     },
     "queue": "default",
     "status": "queued",
     "attempts": 0,
     "max_attempts": 20,
     "run_at": 1000,
     "lease_until": 0,
     "created_at": 1000,
     "updated_at": 1000,
     "last_error": ""
    }
   },
   {
    "method": "POST",
    "path": "/job_queue?now=1000",
    "json": {
     "kind": "sms",
     "max_attempts": 3
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "owner": "alice",
     "kind": "sms",
     "max_attempts": 3,
     "status": "queued",
     "attempts": 0,
     "run_at": 1000
    }
   },
   {
    "method": "POST",
    "path": "/job_queue?now=1000",
    "json": {
     "kind": "push",
     "delay_seconds": 50
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "owner": "bob",
     "kind": "push",
     "status": "queued",
     "run_at": 1050
    }
   },
   {
    "method": "GET",
    "path": "/job_queue/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "owner": "alice",
     "kind": "email",
     "status": "queued"
    }
   },
   {
    "method": "GET",
    "path": "/job_queue/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/job_queue/3",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/job_queue/9999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/job_queue/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/job_queue",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "owner": "alice",
       "kind": "email",
       "payload": {
        "to": "a@x"
       },
       "queue": "default",
       "status": "queued",
       "attempts": 0,
       "max_attempts": 20,
       "run_at": 1000,
       "lease_until": 0,
       "created_at": 1000,
       "updated_at": 1000,
       "last_error": ""
      },
      {
       "id": 2,
       "owner": "alice",
       "kind": "sms",
       "payload": {},
       "queue": "default",
       "status": "queued",
       "attempts": 0,
       "max_attempts": 3,
       "run_at": 1000,
       "lease_until": 0,
       "created_at": 1000,
       "updated_at": 1000,
       "last_error": ""
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/job_queue",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 3,
       "owner": "bob",
       "kind": "push",
       "payload": {},
       "queue": "default",
       "status": "queued",
       "attempts": 0,
       "max_attempts": 20,
       "run_at": 1050,
       "lease_until": 0,
       "created_at": 1000,
       "updated_at": 1000,
       "last_error": ""
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/job_queue",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/job_queue?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "owner": "alice",
       "kind": "email",
       "payload": {
        "to": "a@x"
       },
       "queue": "default",
       "status": "queued",
       "attempts": 0,
       "max_attempts": 20,
       "run_at": 1000,
       "lease_until": 0,
       "created_at": 1000,
       "updated_at": 1000,
       "last_error": ""
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/job_queue?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 2,
       "owner": "alice",
       "kind": "sms",
       "payload": {},
       "queue": "default",
       "status": "queued",
       "attempts": 0,
       "max_attempts": 3,
       "run_at": 1000,
       "lease_until": 0,
       "created_at": 1000,
       "updated_at": 1000,
       "last_error": ""
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/job_queue?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/job_queue?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/job_queue?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/job_queue",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/job_queue/1",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/job_queue/claim?now=1000",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/job_queue/claim?now=1000",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/job_queue/1/complete",
    "json": {
     "lease_token": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "payload": {}
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "a\u001fb"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "max_attempts": 5.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "max_attempts": "5"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "max_attempts": 99999999999999999999
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "max_attempts": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "delay_seconds": -5
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "payload": "notobject"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "payload": {
      "n": 99999999999999999999
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue",
    "json": {
     "kind": "x",
     "max_attempts": true
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue?now=1000",
    "json": {
     "kind": "ma",
     "owner": "bob",
     "id": "forged",
     "status": "done",
     "attempts": 99,
     "lease_token": "forged"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 4,
     "owner": "alice",
     "kind": "ma",
     "status": "queued",
     "attempts": 0,
     "lease_until": 0
    }
   },
   {
    "method": "POST",
    "path": "/job_queue/claim?now=500",
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 204
   },
   {
    "method": "POST",
    "path": "/job_queue/claim?now=2000",
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "owner": "alice",
     "status": "running",
     "attempts": 1
    }
   },
   {
    "method": "POST",
    "path": "/job_queue/1/complete?now=2000",
    "json": {
     "lease_token": "wrongtoken"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/job_queue/1/complete?now=2000",
    "json": {},
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue/9999/complete?now=2000",
    "json": {
     "lease_token": "x"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/job_queue/abc/complete?now=2000",
    "json": {
     "lease_token": "x"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/job_queue/2/complete?now=2000",
    "json": {
     "lease_token": "x"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/job_queue/1/fail?now=2000",
    "json": {
     "lease_token": "wrongtoken"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 409
   }
  ]
 },
 {
  "domain": "ledger",
  "cases": [
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 100
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 1
    }
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 100
      },
      {
       "account_id": 2,
       "amount": -50
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 0
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": "abc"
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 100.0
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": "100"
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 100.5
      },
      {
       "account_id": 2,
       "amount": -100.5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": true
      },
      {
       "account_id": 2,
       "amount": -1
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      null,
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": "nope"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 250
      },
      {
       "account_id": 3,
       "amount": -250
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": 2
    }
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/1/balance",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "account_id": 1,
     "balance": 350
    }
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/2/balance",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "balance": -100
    }
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/3/balance",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "balance": -250
    }
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/999/balance",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "account_id": 999,
     "balance": 0
    }
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/abc/balance",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 5
      },
      {
       "account_id": 2,
       "amount": -5
      }
     ]
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/1/balance",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 5
      },
      {
       "account_id": 2,
       "amount": -5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/1/balance",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": "abc"
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": "abc"
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": "nope"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 100.0
      },
      {
       "account_id": 2,
       "amount": -100
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/abc/balance",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/ledger/accounts/abc/balance",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 5
      },
      {
       "account_id": 2,
       "amount": -5
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ledger/transactions",
    "json": {
     "entries": [
      {
       "account_id": 1,
       "amount": 5
      },
      {
       "account_id": 2,
       "amount": -5
      }
     ]
    },
    "headers": {
     "Authorization": "test:root"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "llm_usage",
  "cases": [
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c1",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000,
     "output_tokens": 500
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000,
     "output_tokens": 500,
     "cost_nanodollars": 7500000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c1",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000,
     "output_tokens": 500
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "cost_nanodollars": 7500000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c1",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 2000,
     "output_tokens": 500
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c2",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000,
     "cost_nanodollars": 999999999
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "cost_nanodollars": 2500000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c3",
     "provider": "openai",
     "model": "gpt-4o",
     "cache_read_input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "cost_nanodollars": 1250000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c4",
     "provider": "openai",
     "model": "gpt-5-ultra",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c5",
     "provider": "openai",
     "model": "gpt-4o",
     "reasoning_tokens": 100
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c6",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1,
     "at": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c7",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": "1000"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c7",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000.5
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c7",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": -1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c7",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": true
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "c8",
     "provider": "",
     "model": "gpt-4o",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "input_tokens": 2000,
     "output_tokens": 500,
     "cache_read_input_tokens": 1000,
     "cost_nanodollars": 11250000
    }
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary?model=",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "input_tokens": 2000,
     "cost_nanodollars": 11250000
    }
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary?model=gpt-4o-mini",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "input_tokens": 0,
     "output_tokens": 0,
     "cost_nanodollars": 0
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "a1",
     "provider": "anthropic",
     "model": "claude-3-5-sonnet",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "cost_nanodollars": 3000000
    }
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "input_tokens": 1000,
     "output_tokens": 0,
     "cost_nanodollars": 3000000
    }
   },
   {
    "method": "GET",
    "path": "/llm_usage/events",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/llm_usage/events?limit=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary?from=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/llm_usage/events?now=1000",
    "json": {
     "identifier": "c9",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "at": 1000,
     "cost_nanodollars": 2500000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events?now=1001",
    "json": {
     "identifier": "c9",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1000
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "at": 1000,
     "cost_nanodollars": 2500000
    }
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "x",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/llm_usage/summary",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/llm_usage/events",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/llm_usage/events",
    "json": {
     "identifier": "x",
     "provider": "openai",
     "model": "gpt-4o",
     "input_tokens": 1
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "notifications",
  "cases": [
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "alice",
     "message": "hello there"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "from": "alice",
     "to": "alice",
     "message": "hello there",
     "status": "unread"
    }
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "bob",
     "message": "hi bob"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "from": "carol",
     "to": "bob",
     "status": "unread"
    }
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "alice",
     "message": "forged?",
     "from": "admin"
    },
    "headers": {
     "Authorization": "Bearer test:mallory"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "from": "mallory",
     "to": "alice",
     "status": "unread"
    }
   },
   {
    "method": "GET",
    "path": "/notifications",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "from": "alice",
       "to": "alice",
       "message": "hello there",
       "status": "unread"
      },
      {
       "id": 3,
       "from": "mallory",
       "to": "alice",
       "message": "forged?",
       "status": "unread"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/notifications?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "from": "alice",
       "to": "alice",
       "message": "hello there",
       "status": "unread"
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/notifications?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 3,
       "from": "mallory",
       "to": "alice",
       "message": "forged?",
       "status": "unread"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/notifications?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/notifications?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/notifications?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/notifications?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications/1/read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "from": "alice",
     "status": "read",
     "message": "hello there"
    }
   },
   {
    "method": "POST",
    "path": "/notifications/1/read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "status": "read"
    }
   },
   {
    "method": "POST",
    "path": "/notifications/1/read",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/notifications/999999/read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/notifications",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/notifications",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/notifications",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x",
     "message": "m"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x",
     "message": "m"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x",
     "message": "m"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "",
     "message": "m"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/notifications/abc/read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": 7,
     "message": "m"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "",
     "message": "m"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x",
     "message": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/notifications",
    "json": {
     "to": "x",
     "message": true
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "oauth",
  "cases": [
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "google",
     "state": "s1"
    },
    "status": 201,
    "expect": {
     "provider": "google",
     "state": "s1",
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "google",
     "state": "s1"
    },
    "status": 201,
    "expect": {
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "s1",
     "code": "c1"
    },
    "status": 200,
    "expect": {
     "provider": "google",
     "state": "s1",
     "status": "authorized"
    }
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "s1",
     "code": "c1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "google",
     "state": "s1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "sFORGED",
     "code": "c1"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "github",
     "state": "s2"
    },
    "status": 201,
    "expect": {
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "s2",
     "code": "c2"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "github",
     "state": "s2",
     "code": "c2"
    },
    "status": 200,
    "expect": {
     "status": "authorized"
    }
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "myspace",
     "state": "x"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "myspace",
     "state": "x",
     "code": "c"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "google"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": "google",
     "state": ""
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/authorize",
    "json": {
     "provider": 7,
     "state": "x"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "s1"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/oauth/callback",
    "json": {
     "provider": "google",
     "state": "s1",
     "code": true
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "orgs",
  "cases": [
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "acme"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "slug": "acme",
     "owner": "alice",
     "status": "active"
    }
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "acme"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 409
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "acme",
     "owner": "alice"
    }
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "bob",
     "role": "admin"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "slug": "acme",
     "handle": "bob",
     "role": "admin",
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "dan",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "carol",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "handle": "carol",
     "role": "member",
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "dave",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "carol",
     "role": "admin"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "mallory",
     "role": "owner"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "eve",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "frank",
     "role": "member"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {
     "owner": "carol"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {
     "owner": "bob"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "acme",
     "owner": "bob",
     "status": "active"
    }
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "bob"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "dave",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "handle": "dave",
     "role": "member",
     "status": "pending"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {
     "owner": "carol"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members/accept",
    "json": {
     "token": "no.invite"
    },
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/ghost/members/accept",
    "json": {
     "token": "x.y"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members/accept",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members/accept",
    "json": {
     "token": ""
    },
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members/accept",
    "json": {
     "token": "x.y"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/p%1Fq/members/accept",
    "json": {
     "token": "x.y"
    },
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/dave",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "acme",
     "handle": "dave",
     "removed": true
    }
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/dave",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "removed": true
    }
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/bob",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/alice",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/alice",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/acme/archive",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/orgs/acme/archive",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "acme",
     "status": "archived"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/acme/archive",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "status": "archived"
    }
   },
   {
    "method": "GET",
    "path": "/orgs/acme",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "status": "archived",
     "owner": "bob"
    }
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {
     "owner": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/acme/archive",
    "json": {},
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/ghost/transfer",
    "json": {
     "owner": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/ghost/archive",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/ghost/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/orgs/ghost/members/x",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/ghost",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/orgs/a%2Fb",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/a%2fb",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/x%2Fy",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "listorg"
    },
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 201,
    "expect": {
     "owner": "lou"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/transfer",
    "json": {
     "owner": "bea"
    },
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 200,
    "expect": {
     "owner": "bea"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/members",
    "json": {
     "handle": "cleo",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 201,
    "expect": {
     "status": "pending"
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "handle": "bea",
       "role": "owner"
      },
      {
       "handle": "lou",
       "role": "admin"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "handle": "bea",
       "role": "owner"
      },
      {
       "handle": "lou",
       "role": "admin"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:cleo"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/invitations",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/invitations",
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/invitations",
    "headers": {
     "Authorization": "Bearer test:cleo"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/invitations",
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/invitations",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members?limit=1",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "handle": "bea",
       "role": "owner"
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members?limit=0",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members?cursor=bogus",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/orgs",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs",
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs",
    "headers": {
     "Authorization": "Bearer test:nobodyy"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/orgs",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/leave",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/leave",
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 200,
    "expect": {
     "slug": "listorg",
     "handle": "lou",
     "left": true
    }
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:lou"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/listorg/members",
    "headers": {
     "Authorization": "Bearer test:bea"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "handle": "bea",
       "role": "owner"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/leave",
    "headers": {
     "Authorization": "Bearer test:zoe"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/listorg/leave",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/orgs/ghost/members",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/ghost/invitations",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/orgs/ghost/leave",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/orgs/p%1Fq/members",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/p%1Fq/leave",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {
     "owner": ""
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/transfer",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "x"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs/acme/members",
    "json": {
     "handle": "",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/orgs/acme/members/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "payments",
  "cases": [
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "status": "authorized",
     "amount": 2000,
     "currency": "usd",
     "amount_captured": 0,
     "amount_voided": 0,
     "amount_refunded": 0
    }
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "status": "authorized",
     "amount": 2000,
     "currency": "usd"
    }
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 999,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "eur"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 100,
     "currency": "eur"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K2"
    },
    "status": 201,
    "expect": {
     "status": "authorized",
     "amount": 100,
     "currency": "eur"
    }
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 5,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 5,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": ""
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 0,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 9007199254740992,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 500.0,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": "x",
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 10,
     "currency": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 10,
     "currency": "xyz"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "Z"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 0,
     "currency": "usd"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/payments",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/payments?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/payments?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/payments",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/payments/nope",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/payments/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/payments/nope",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments/nope/capture",
    "json": {
     "amount": 100
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/payments/nope/capture",
    "json": {
     "amount": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/capture",
    "json": {
     "amount": 500.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/capture",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/capture",
    "json": {
     "amount": 100
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments/p%1Fq/capture",
    "json": {
     "amount": 100
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/void",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/payments/nope/void",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/payments/nope/refund",
    "json": {
     "amount": 100
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "RF"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/payments/nope/refund",
    "json": {
     "amount": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "RF"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/refund",
    "json": {
     "amount": 100
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/payments/nope/refund",
    "json": {
     "amount": 100
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "prompt_registry",
  "cases": [
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions?now=1700000000",
    "json": {
     "template": "Hi {{name}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "greeting",
     "version": 1,
     "content_hash": "deeba1bc3365b21a1114b846653b300411236d39777fb54653dad310e4b7d445",
     "created_at": 1700000000
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": "Hello {{name}}!"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "greeting",
     "version": 2,
     "content_hash": "0ac46560e041dd7ae408035089e631b9bef26d90d7e763b5eabfb947c41d05a3"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "greeting",
     "version": 1,
     "template": "Hi {{name}}",
     "content_hash": "deeba1bc3365b21a1114b846653b300411236d39777fb54653dad310e4b7d445"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/2",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 2,
     "template": "Hello {{name}}!"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/forge/versions",
    "json": {
     "template": "X",
     "content_hash": "forged-value-must-be-discarded"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "forge",
     "version": 1,
     "content_hash": "4b68ab3847feda7d6c62c1fbcbeebfa35eab7351ed5e78f4ddadea5df64b8015"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1,
     "data": {
      "name": "Ada"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "greeting",
     "version": 1,
     "content_hash": "deeba1bc3365b21a1114b846653b300411236d39777fb54653dad310e4b7d445",
     "rendered": "Hi Ada"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 2,
     "data": {
      "name": "Bob"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 2,
     "rendered": "Hello Bob!"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/inject/versions",
    "json": {
     "template": "{{x}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/inject/render",
    "json": {
     "version": 1,
     "data": {
      "x": "{{y}}",
      "y": "SECRET"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 1,
     "rendered": "{{y}}"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/inject/render",
    "json": {
     "version": 1,
     "data": {
      "x": "{{x}}"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "rendered": "{{x}}"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/inject/render",
    "json": {
     "version": 1,
     "data": {}
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1,
     "data": {
      "name": 7
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/ascii/versions",
    "json": {
     "template": "v={{a_1}} lit={{\u00e9}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/ascii/render",
    "json": {
     "version": 1,
     "data": {
      "a_1": "X"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "rendered": "v=X lit={{\u00e9}}"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/amp/versions",
    "json": {
     "template": "{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}{{a}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/amp/render",
    "json": {
     "version": 1,
     "data": {
      "a": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1,
     "label": "production",
     "data": {
      "name": "A"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "data": {
      "name": "A"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/production",
    "json": {
     "version": 2
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "greeting",
     "label": "production",
     "version": 2
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "label": "production",
     "data": {
      "name": "Z"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 2,
     "rendered": "Hello Z!"
    }
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/production",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "label": "production",
     "data": {
      "name": "Z"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 1,
     "rendered": "Hi Z"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": "third {{name}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "version": 3
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "label": "production",
     "data": {
      "name": "Z"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 1,
     "rendered": "Hi Z"
    }
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/bad",
    "json": {
     "version": 99
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "label": "ghost",
     "data": {
      "name": "Z"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "greeting",
     "latest_version": 3,
     "version_count": 3,
     "labels": {
      "production": 1
     }
    }
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {
     "version": 1.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {
     "version": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {
     "version": "1"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1.0,
     "data": {
      "name": "A"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 9007199254740993,
     "data": {
      "name": "A"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1.0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/99",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1,
     "data": {
      "name": "A"
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": "BOB ONLY"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "name": "greeting",
     "version": 1,
     "content_hash": "367533d52bbdc9bdf99907bbf0402bde7972cbcc729034590343fc376634e539"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "version": 1,
     "template": "BOB ONLY"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "version": 1,
     "template": "Hi {{name}}"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/massassign/versions",
    "json": {
     "template": "X",
     "owner": "bob",
     "version": 99,
     "created_at": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "massassign",
     "version": 1
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/massassign",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/massassign",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "massassign",
     "latest_version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/p%1Fq/versions",
    "json": {
     "template": "X"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/l%1Fq",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/a%2Fb",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/versions/versions",
    "json": {
     "template": "meta {{m}}"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "name": "versions",
     "version": 1,
     "content_hash": "9eb8c67787ea339cee59f59d7ba1e948454f12ef36d2198a318b2de38c7516f2"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/versions/versions/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "name": "versions",
     "version": 1,
     "template": "meta {{m}}"
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/aaa/versions",
    "json": {
     "template": "a"
    },
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 201,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/bbb/versions",
    "json": {
     "template": "b"
    },
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 201,
    "expect": {
     "version": 1
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "aaa",
       "latest_version": 1
      },
      {
       "name": "bbb",
       "latest_version": 1
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts?limit=1",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "aaa",
       "latest_version": 1
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "name": "bbb",
       "latest_version": 1
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts?limit=0",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts?limit=abc",
    "headers": {
     "Authorization": "Bearer test:lister"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": "X"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/versions",
    "json": {
     "template": "X"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting/versions/1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/prompt_registry/prompts/greeting",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/prompt_registry/prompts/greeting/labels/x",
    "json": {
     "version": 1
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/prompt_registry/prompts/greeting/render",
    "json": {
     "version": 1,
     "data": {
      "name": "A"
     }
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "rag",
  "cases": [
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "the quick brown fox jumps over the lazy dog"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "doc_id": "d1",
     "chunks": 1
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "the quick brown fox jumps over the lazy dog"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d2",
     "text": "lazy dogs sleep peacefully all day long"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "doc_id": "d2",
     "chunks": 1
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "lazy dogs sleep peacefully all day long",
     "k": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d2#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "doc_id": "d1",
     "chunks": 1
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "the quick brown fox jumps over the lazy dog",
     "k": 50
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "text": "no id"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "",
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": 7,
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d9"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d9",
     "text": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d9",
     "text": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x",
     "k": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x",
     "k": 2.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x",
     "k": "many"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x",
     "k": 51
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x",
     "k": 9007199254740992
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": null,
     "hits": []
    }
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "b1",
     "text": "bob private knowledge corpus"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "doc_id": "b1",
     "chunks": 1
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "bob private knowledge corpus"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "b1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "b1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "bobs separate document number one"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "doc_id": "d1",
     "chunks": 1
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "completely different content entirely now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "bobs separate document number one"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "d1#0"
    }
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "d1",
     "text": "x"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/documents",
    "json": {
     "doc_id": "",
     "text": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": "x"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rag/query",
    "json": {
     "query": ""
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "ratelimit",
  "cases": [
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1000",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 4
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1001",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 3
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1002",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 2
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1003",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 1
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1004",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 0
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1005",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 429
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1006",
    "json": {
     "key": "bob"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 4
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1020",
    "json": {
     "key": "alice"
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 200,
    "expect": {
     "allowed": true,
     "remaining": 4
    }
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1000",
    "json": {},
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1000",
    "json": {
     "key": 7
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1000",
    "json": {
     "key": ""
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=1000",
    "json": {
     "key": true
    },
    "headers": {
     "Authorization": "Bearer service_dev_token_change_me"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=9000",
    "json": {
     "key": "probe"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=9000",
    "json": {
     "key": "probe"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/ratelimit/check?now=9000",
    "json": {
     "key": 7
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "rbac",
  "cases": [
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "viewer"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=write",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "editor"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=write",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=delete",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "mallory",
     "role": "superuser"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "Bearer test:mallory"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "admin"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {},
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=delete",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc1",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner",
     "object": "doc1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc1",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc1",
    "headers": {
     "Authorization": "Bearer test:u2"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc2",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=editor&object=doc1",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner",
     "object": "doc1"
    },
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "viewer"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner",
     "object": "doc1"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": 7,
     "role": "viewer"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "",
     "role": "viewer"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": true
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": 5,
     "object": "doc1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/can",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=p%1Fq&object=s",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "editor"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "removed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=write",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "GET",
    "path": "/rbac/can?permission=read",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "DELETE",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "editor"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "removed": false
    }
   },
   {
    "method": "DELETE",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner",
     "object": "doc1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "removed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/check?relation=owner&object=doc1",
    "headers": {
     "Authorization": "Bearer test:u1"
    },
    "status": 200,
    "expect": {
     "allowed": false
    }
   },
   {
    "method": "DELETE",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner",
     "object": "doc1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "removed": false
    }
   },
   {
    "method": "DELETE",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "viewer"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "DELETE",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice",
     "role": "viewer"
    },
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/rbac/roles",
    "json": {
     "subject": "alice"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/rbac/relations",
    "json": {
     "subject": "u1",
     "relation": "owner"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "carol",
     "role": "editor"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "POST",
    "path": "/rbac/roles",
    "json": {
     "subject": "carol",
     "role": "viewer"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "editor",
      "viewer"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/rbac/roles",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [
      "editor",
      "viewer"
     ]
    }
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol",
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&limit=1",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "editor"
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "viewer"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&cursor=OTAwNzE5OTI1NDc0MDk5Mw",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&limit=0",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/roles?subject=carol&limit=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "carol",
     "relation": "owner",
     "object": "docA"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "POST",
    "path": "/rbac/relations",
    "json": {
     "subject": "carol",
     "relation": "owner",
     "object": "docB"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "allowed": true
    }
   },
   {
    "method": "GET",
    "path": "/rbac/relations?subject=carol",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "subject": "carol",
       "relation": "owner",
       "object": "docA"
      },
      {
       "subject": "carol",
       "relation": "owner",
       "object": "docB"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/rbac/relations?object=docA",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "subject": "carol",
       "relation": "owner",
       "object": "docA"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/rbac/relations?object=docA",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/rbac/relations?subject=carol",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/rbac/relations",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/rbac/decisions",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200
   },
   {
    "method": "GET",
    "path": "/rbac/decisions",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/rbac/decisions",
    "status": 401
   }
  ]
 },
 {
  "domain": "records",
  "cases": [
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "alpha-1",
     "fields": {
      "title": "alpha"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "created_at": 1700000000,
     "updated_at": 1700000000,
     "fields": {
      "title": "alpha"
     }
    }
   },
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "alpha-2",
     "fields": {
      "title": "second",
      "count": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "second",
      "count": 5
     }
    }
   },
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "bob-1",
     "fields": {
      "title": "bobs note"
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "owner": "bob",
     "fields": {
      "title": "bobs note"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "alpha"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/records/6f87780cc14e81fdb2446c403747ffcc37d3040917f16a729b3c0072157f8153",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/records/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/records",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
       "owner": "alice",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "second",
        "count": 5
       }
      },
      {
       "id": "fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
       "owner": "alice",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "alpha"
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/records",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "6f87780cc14e81fdb2446c403747ffcc37d3040917f16a729b3c0072157f8153",
       "owner": "bob",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "bobs note"
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/records",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/records?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
       "owner": "alice",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "second",
        "count": 5
       }
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/records?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
       "owner": "alice",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "alpha"
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/records?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/records?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/records?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PATCH",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39?now=1700000100",
    "json": {
     "fields": {
      "count": 9,
      "status": "open"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "alice",
     "updated_at": 1700000100,
     "fields": {
      "title": "alpha",
      "count": 9,
      "status": "open"
     }
    }
   },
   {
    "method": "PATCH",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "json": {
     "fields": {
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/records/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "json": {
     "fields": {
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39?now=1700000150",
    "json": {
     "fields": {
      "count": 1
     },
     "owner": "bob",
     "created_at": 0,
     "id": "forged"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "alice",
     "created_at": 1700000000,
     "updated_at": 1700000150,
     "fields": {
      "title": "alpha",
      "count": 1,
      "status": "open"
     }
    }
   },
   {
    "method": "DELETE",
    "path": "/records/ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/records/ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/records/ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "PATCH",
    "path": "/records/ba32a5c47c5a1d6582c2dd526372ca236eda371ff2d8c091b05e5b36097bb845",
    "json": {
     "fields": {
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "dur",
     "fields": {
      "title": "t",
      "count": 3,
      "done": true,
      "due": "2126-06-28T10:30:00Z",
      "day": "2126-03-15",
      "status": "closed",
      "meta": {
       "a": 1
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "t",
      "count": 3,
      "done": true,
      "due": "2126-06-28T10:30:00Z",
      "day": "2126-03-15",
      "status": "closed",
      "meta": {
       "a": 1
      }
     }
    }
   },
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "massassign",
     "fields": {
      "title": "m",
      "owner": "bob",
      "id": "forged"
     },
     "owner": "bob",
     "type": "evil"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "m"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/582ed7feeda8e2e98698bb72a46855721c2d021a0a866f835b31423a772b1c16",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/records/582ed7feeda8e2e98698bb72a46855721c2d021a0a866f835b31423a772b1c16",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "m"
     }
    }
   },
   {
    "method": "POST",
    "path": "/records?now=1700000000",
    "json": {
     "key": "unknownstrip",
     "fields": {
      "title": "u",
      "unknown": "y",
      "Owner": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "fields": {
      "title": "u"
     }
    }
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v1",
     "fields": {
      "title": "x",
      "count": "NaN"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v2",
     "fields": {
      "count": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v3",
     "fields": {
      "title": "x",
      "status": "bad"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v4",
     "fields": {
      "title": "x",
      "due": "not-a-date"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v5",
     "fields": {
      "title": "x",
      "done": "yes"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v6",
     "fields": {
      "title": "x",
      "count": 99999999999999999999
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "",
     "fields": {
      "title": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "bad\u001fkey",
     "fields": {
      "title": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "fields": {
      "title": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "v7",
     "fields": "notobject"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "vd1",
     "fields": {
      "title": "x",
      "day": "2126-13-45"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "vd2",
     "fields": {
      "title": "x",
      "day": "not-a-date"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "vdt",
     "fields": {
      "title": "x",
      "due": "2126-01-01T00:00:00Z\n"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "vbj",
     "fields": {
      "title": "x",
      "meta": {
       "n": 99999999999999999999
      }
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/records",
    "json": {
     "key": "x",
     "fields": {
      "title": "y"
     }
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/records",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "status": 401
   },
   {
    "method": "PATCH",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "json": {
     "fields": {
      "count": 1
     }
    },
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/records/fcc198e9899df0bd2eb5791ab7454638d5c0ef3717763ce18e5faa2fef546d39",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/records",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/records",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "recshare"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "slug": "recshare",
     "owner": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/recshare/transfer",
    "json": {
     "owner": "bob"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "recshare",
     "owner": "bob"
    }
   },
   {
    "method": "POST",
    "path": "/records?org=recshare&now=1700000000",
    "json": {
     "key": "deal-1",
     "fields": {
      "title": "lead"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "recshare",
     "scope": "org",
     "created_at": 1700000000,
     "updated_at": 1700000000,
     "fields": {
      "title": "lead"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/a7255bcbba943fd4723bd42ae50305d06198a2d2c18988f74aa7395eab64fa35?org=recshare",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "owner": "recshare",
     "scope": "org",
     "fields": {
      "title": "lead"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/a7255bcbba943fd4723bd42ae50305d06198a2d2c18988f74aa7395eab64fa35?org=recshare",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "owner": "recshare",
     "scope": "org",
     "fields": {
      "title": "lead"
     }
    }
   },
   {
    "method": "GET",
    "path": "/records/a7255bcbba943fd4723bd42ae50305d06198a2d2c18988f74aa7395eab64fa35?org=recshare",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/records?org=recshare",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "a7255bcbba943fd4723bd42ae50305d06198a2d2c18988f74aa7395eab64fa35",
       "owner": "recshare",
       "created_at": 1700000000,
       "updated_at": 1700000000,
       "fields": {
        "title": "lead"
       },
       "scope": "org"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/records?org=recshare",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/records?org=recshare",
    "json": {
     "key": "out-1",
     "fields": {
      "title": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/records?org=recshare",
    "json": {
     "key": "anon-1",
     "fields": {
      "title": "x"
     }
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/records?org=recshare&now=1700000000",
    "json": {
     "key": "deal-2",
     "fields": {
      "title": "lead2"
     },
     "owner": "evil"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "recshare",
     "scope": "org",
     "fields": {
      "title": "lead2"
     }
    }
   },
   {
    "method": "POST",
    "path": "/records?org=p%1Fq",
    "json": {
     "key": "x",
     "fields": {
      "title": "x"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "reporting",
  "cases": [
   {
    "method": "POST",
    "path": "/reporting/facts?now=1700000000",
    "json": {
     "dataset": "deals",
     "key": "d1",
     "dimensions": {
      "stage": "won",
      "region": "eu"
     },
     "measures": {
      "value": 100,
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "dataset": "deals",
     "key": "d1",
     "dimensions": {
      "stage": "won",
      "region": "eu"
     },
     "measures": {
      "value": 100,
      "count": 1
     },
     "created_at": 1700000000
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "d2",
     "dimensions": {
      "stage": "won",
      "region": "us"
     },
     "measures": {
      "value": 250,
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "dataset": "deals",
     "dimensions": {
      "stage": "won",
      "region": "us"
     },
     "measures": {
      "value": 250,
      "count": 1
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "d3",
     "dimensions": {
      "stage": "lost",
      "region": "eu"
     },
     "measures": {
      "value": 50,
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "value": 50,
      "count": 1
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "d1",
     "dimensions": {
      "stage": "changed",
      "region": "zz"
     },
     "measures": {
      "value": 99999,
      "count": 9
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "dataset": "deals",
     "key": "d1",
     "dimensions": {
      "stage": "won",
      "region": "eu"
     },
     "measures": {
      "value": 100,
      "count": 1
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "dx",
     "dimensions": {
      "stage": "won",
      "region": "eu"
     },
     "measures": {
      "value": 999,
      "count": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "owner": "bob",
     "measures": {
      "value": 999,
      "count": 1
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [],
     "aggregate": [
      {
       "op": "count"
      },
      {
       "op": "sum",
       "field": "value",
       "as": "total"
      },
      {
       "op": "min",
       "field": "value",
       "as": "lo"
      },
      {
       "op": "max",
       "field": "value",
       "as": "hi"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {},
       "values": {
        "count": 3,
        "total": 400,
        "lo": 50,
        "hi": 250
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [
      "stage"
     ],
     "aggregate": [
      {
       "op": "count"
      },
      {
       "op": "sum",
       "field": "value",
       "as": "total"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {
        "stage": "lost"
       },
       "values": {
        "count": 1,
        "total": 50
       }
      },
      {
       "key": {
        "stage": "won"
       },
       "values": {
        "count": 2,
        "total": 350
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [
      "stage"
     ],
     "filter": {
      "region": "eu"
     },
     "aggregate": [
      {
       "op": "count"
      },
      {
       "op": "sum",
       "field": "value",
       "as": "total"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {
        "stage": "lost"
       },
       "values": {
        "count": 1,
        "total": 50
       }
      },
      {
       "key": {
        "stage": "won"
       },
       "values": {
        "count": 1,
        "total": 100
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [],
     "aggregate": [
      {
       "op": "sum",
       "field": "value",
       "as": "total"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {},
       "values": {
        "total": 999
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [],
     "aggregate": [
      {
       "op": "sum",
       "field": "value",
       "as": "total"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 200,
    "expect": {
     "groups": [],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "sparse",
     "key": "s1",
     "dimensions": {
      "g": "a"
     },
     "measures": {
      "x": 10
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "x": 10
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "sparse",
     "key": "s2",
     "dimensions": {
      "g": "a"
     },
     "measures": {
      "y": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "y": 5
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "sparse",
     "group_by": [
      "g"
     ],
     "aggregate": [
      {
       "op": "count"
      },
      {
       "op": "sum",
       "field": "x",
       "as": "sx"
      },
      {
       "op": "min",
       "field": "x",
       "as": "mnx"
      },
      {
       "op": "max",
       "field": "x",
       "as": "mxx"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {
        "g": "a"
       },
       "values": {
        "count": 2,
        "sx": 10,
        "mnx": 10,
        "mxx": 10
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "sparse",
     "group_by": [
      "g"
     ],
     "aggregate": [
      {
       "op": "count"
      },
      {
       "op": "min",
       "field": "z",
       "as": "mnz"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {
        "g": "a"
       },
       "values": {
        "count": 2
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "big",
     "key": "b1",
     "measures": {
      "v": 9007199254740991
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "v": 9007199254740991
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "big",
     "key": "b2",
     "measures": {
      "v": 2
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "v": 2
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "big",
     "group_by": [],
     "aggregate": [
      {
       "op": "sum",
       "field": "v",
       "as": "s"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "big",
     "group_by": [],
     "aggregate": [
      {
       "op": "max",
       "field": "v",
       "as": "m"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "groups": [
      {
       "key": {},
       "values": {
        "m": 9007199254740991
       }
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "ok",
     "measures": {
      "n": 5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "measures": {
      "n": 5
     }
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f1",
     "measures": {
      "n": 5.0
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f2",
     "measures": {
      "n": 5.5
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f3",
     "measures": {
      "n": "5"
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f4",
     "measures": {
      "n": true
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f5",
     "measures": {
      "n": 9007199254740992
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f6",
     "dimensions": {
      "x": 7
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "f7",
     "dimensions": {
      "x": null
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "",
     "key": "f8"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": "bad\u001fkey"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "key": "f9"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "val",
     "key": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "colon",
     "key": "a:b",
     "dimensions": {
      "stage": "x"
     },
     "measures": {
      "v": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "key": "a:b"
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "colon:",
     "key": "b",
     "dimensions": {
      "stage": "y"
     },
     "measures": {
      "v": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice",
     "dataset": "colon:"
    }
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [
      "stage"
     ],
     "aggregate": []
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "aggregate": [
      {
       "op": "count",
       "field": "value"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "aggregate": [
      {
       "op": "sum"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "aggregate": [
      {
       "op": "median",
       "field": "value"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "aggregate": [
      {
       "op": "sum",
       "field": "value",
       "as": "t"
      },
      {
       "op": "max",
       "field": "value",
       "as": "t"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "group_by": [
      7
     ],
     "aggregate": [
      {
       "op": "count"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "filter": {
      "region": 7
     },
     "aggregate": [
      {
       "op": "count"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "aggregate": [
      {
       "op": "count"
      }
     ]
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts?now=1700000000",
    "json": {
     "dataset": "temp",
     "key": "t1",
     "dimensions": {
      "region": "eu"
     },
     "measures": {
      "v": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts?now=1700000000",
    "json": {
     "dataset": "temp",
     "key": "t2",
     "dimensions": {
      "region": "us"
     },
     "measures": {
      "v": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "owner": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/reporting/facts?now=1700000000",
    "json": {
     "dataset": "temp",
     "key": "tb",
     "dimensions": {
      "region": "eu"
     },
     "measures": {
      "v": 1
     }
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "owner": "bob"
    }
   },
   {
    "method": "DELETE",
    "path": "/reporting/facts?dataset=temp&region=eu",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "deleted": 1
    }
   },
   {
    "method": "GET",
    "path": "/reporting/facts?dataset=temp",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "48316ae1d1ef6ffb11d317cae7398e8a349b887450ec24b331e2a259b7d1e4ed",
       "owner": "alice",
       "dataset": "temp",
       "key": "t2",
       "dimensions": {
        "region": "us"
       },
       "measures": {
        "v": 1
       },
       "created_at": 1700000000
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "DELETE",
    "path": "/reporting/facts?dataset=temp",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "deleted": 1
    }
   },
   {
    "method": "GET",
    "path": "/reporting/facts?dataset=temp",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/reporting/facts?dataset=temp",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": "28108b90e3a5a42892228c0cc2af9744f3c4fe9171c36d986ef6759527636b15",
       "owner": "bob",
       "dataset": "temp",
       "key": "tb",
       "dimensions": {
        "region": "eu"
       },
       "measures": {
        "v": 1
       },
       "created_at": 1700000000
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "DELETE",
    "path": "/reporting/facts",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/reporting/facts?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/reporting/facts?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "z"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "z"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/reporting/facts",
    "json": {
     "dataset": "deals",
     "key": "z"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/reporting/facts",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/reporting/query",
    "json": {
     "dataset": "deals",
     "aggregate": [
      {
       "op": "count"
      }
     ]
    },
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/reporting/facts?dataset=deals",
    "status": 401
   }
  ]
 },
 {
  "domain": "search",
  "cases": [
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 1,
     "text": "The quick brown fox"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "tokens": 4
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 2,
     "text": "the lazy dog sleeps"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "tokens": 4
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 3,
     "text": "quick quick dog"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "tokens": 2
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      3,
      1
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick%20dog",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      3
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=THE",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      1,
      2
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=qui",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=missingword",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick%20missingword",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 1,
     "text": "replaced entirely"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "tokens": 2
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      3
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=replaced",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      1
     ]
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 50,
     "text": "bob private quick secret"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 50,
     "tokens": 4
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      50
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=secret",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      50
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      3
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=secret",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=replaced",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=dog",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 99,
     "text": "alphaword sharednine"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 99,
     "tokens": 2
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 99,
     "text": "betaword sharednine"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 99,
     "tokens": 2
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=alphaword",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      99
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=betaword",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      99
     ]
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=betaword",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "GET",
    "path": "/search/query?q=alphaword",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": []
    }
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 4
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 0,
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 2.0,
     "text": "y"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": "x",
     "text": "y"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 4,
     "text": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 4,
     "text": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 5,
     "text": "anonymous write must be refused"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 5,
     "text": "stale token must be refused"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 5,
     "text": "non-bearer scheme must be refused"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/search/index",
    "json": {
     "id": 0,
     "text": "x"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/search/query",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/search/query?q=quick",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "secrets_vault",
  "cases": [
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": "hunter2"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "db_password",
     "version": 1
    }
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": "correct-horse"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "db_password",
     "version": 2
    }
   },
   {
    "method": "GET",
    "path": "/secrets_vault/db_password",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "db_password",
     "current_version": 2
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "db_password",
     "version": 2,
     "value": "correct-horse"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "db_password",
     "version": 1,
     "value": "hunter2"
    }
   },
   {
    "method": "GET",
    "path": "/secrets_vault",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "db_password"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 99
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/secrets_vault/ghost",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/secrets_vault/ghost/reveal",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/secrets_vault/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 1.0
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": ""
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": 7
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 0
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": "two"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": "1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/api_key",
    "json": {
     "value": "k-secret"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "api_key",
     "version": 1
    }
   },
   {
    "method": "GET",
    "path": "/secrets_vault?limit=1",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "api_key"
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/secrets_vault?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "results": [
      "db_password"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/secrets_vault?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/secrets_vault?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/secrets_vault?limit=0",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/secrets_vault?limit=abc",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/secrets_vault",
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": "x"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault/db_password",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {},
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault",
    "headers": {
     "Authorization": "test:root"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/secrets_vault/db_password",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {},
    "status": 401
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 1.0
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault/p%1Fq",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/secrets_vault/db_password/reveal",
    "json": {
     "version": 1.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/db_password",
    "json": {
     "value": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/rotated",
    "json": {
     "value": "r1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "rotated",
     "version": 1
    }
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/rotated",
    "json": {
     "value": "r2"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "rotated",
     "version": 2
    }
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/rotated",
    "json": {
     "value": "r3"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "name": "rotated",
     "version": 3
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/destroy",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "version": 1,
     "state": "destroyed"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/reveal",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/secrets_vault/rotated",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "current_version": 3,
     "states": {
      "1": "destroyed"
     }
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/disable",
    "json": {
     "version": 2
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "version": 2,
     "state": "disabled"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/reveal",
    "json": {
     "version": 2
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/enable",
    "json": {
     "version": 2
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "version": 2,
     "state": "enabled"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/reveal",
    "json": {
     "version": 2
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "version": 2,
     "value": "r2"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/reveal",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "name": "rotated",
     "version": 3,
     "value": "r3"
    }
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/destroy",
    "json": {
     "version": 99
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/secrets_vault/ghost/destroy",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/destroy",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/disable",
    "json": {
     "version": 0
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/disable",
    "json": {
     "version": "1"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/enable",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/destroy",
    "json": {
     "version": 1
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/destroy",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/disable",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/secrets_vault/rotated/enable",
    "json": {
     "version": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "PUT",
    "path": "/secrets_vault/access",
    "json": {
     "value": "x"
    },
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/secrets_vault/access",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200
   },
   {
    "method": "GET",
    "path": "/secrets_vault/access",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/secrets_vault/access",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   }
  ]
 },
 {
  "domain": "settings",
  "cases": [
   {
    "method": "GET",
    "path": "/settings",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "notifications_enabled": true,
     "items_per_page": 20,
     "theme": "light"
    }
   },
   {
    "method": "GET",
    "path": "/settings/theme",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "theme",
     "value": "light"
    }
   },
   {
    "method": "PUT",
    "path": "/settings/theme",
    "json": {
     "value": "dark"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "theme",
     "value": "dark"
    }
   },
   {
    "method": "PUT",
    "path": "/settings/items_per_page",
    "json": {
     "value": 50
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "items_per_page",
     "value": 50
    }
   },
   {
    "method": "PUT",
    "path": "/settings/notifications_enabled",
    "json": {
     "value": false
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "notifications_enabled",
     "value": false
    }
   },
   {
    "method": "GET",
    "path": "/settings",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "notifications_enabled": false,
     "items_per_page": 50,
     "theme": "dark"
    }
   },
   {
    "method": "GET",
    "path": "/settings",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "notifications_enabled": true,
     "items_per_page": 20,
     "theme": "light"
    }
   },
   {
    "method": "GET",
    "path": "/settings",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/settings/theme",
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/settings/theme",
    "json": {
     "value": "dark"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/settings",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/settings",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "PUT",
    "path": "/settings/items_per_page",
    "json": {
     "value": "50"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/items_per_page",
    "json": {
     "value": 1.5
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/items_per_page",
    "json": {
     "value": 50.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/items_per_page",
    "json": {
     "value": true
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/notifications_enabled",
    "json": {
     "value": "yes"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/notifications_enabled",
    "json": {
     "value": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/theme",
    "json": {
     "value": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/unknown_key",
    "json": {
     "value": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "PUT",
    "path": "/settings/theme",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/settings/unknown_key",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   }
  ]
 },
 {
  "domain": "storage",
  "cases": [
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "a.txt",
     "content": "hello world"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "key": "a.txt",
     "provider": "store",
     "size": 11,
     "etag": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    }
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "a.txt",
     "content": "hello world",
     "size": 11,
     "etag": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    }
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "copy.txt",
     "content": "hello world"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "etag": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    }
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "empty.bin",
     "content": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "size": 0,
     "etag": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
   },
   {
    "method": "GET",
    "path": "/storage",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      "a.txt",
      "copy.txt",
      "empty.bin"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/storage?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      "a.txt"
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/storage?cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      "copy.txt",
      "empty.bin"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/storage?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/storage?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/storage?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/storage?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "a.txt",
     "content": "bob's own bytes"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "key": "a.txt",
     "provider": "store",
     "size": 15,
     "etag": "525e766b2aa80414bcc88d9e9546054515e49bbfb61abedc2d0c877cf1b9f9e4"
    }
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "key": "a.txt",
     "content": "bob's own bytes",
     "size": 15,
     "etag": "525e766b2aa80414bcc88d9e9546054515e49bbfb61abedc2d0c877cf1b9f9e4"
    }
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "key": "a.txt",
     "content": "hello world",
     "size": 11,
     "etag": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    }
   },
   {
    "method": "GET",
    "path": "/storage",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      "a.txt"
     ],
     "next_cursor": null
    }
   },
   {
    "method": "DELETE",
    "path": "/storage/copy.txt",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/storage/empty.bin",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/storage/missing.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 204
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "DELETE",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "content": "bob's own bytes"
    }
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "a.txt",
     "content": "x"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/storage",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/storage/a.txt",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/storage/a.txt",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/storage",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/storage",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/storage/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/storage/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/storage/p%1Fq",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "",
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": 7,
     "content": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "k"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/storage",
    "json": {
     "key": "k",
     "content": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "stripe",
  "cases": [
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": "ch_1",
     "amount": 2000,
     "currency": "usd",
     "status": "succeeded"
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": "ch_1"
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 999,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K1"
    },
    "status": 409
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 100,
     "currency": "eur"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": "K2"
    },
    "status": 201,
    "expect": {
     "id": "ch_2",
     "currency": "eur"
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 50,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "ch_3"
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 50,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "ch_4"
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 3000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:bob",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": "ch_5",
     "amount": 3000
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 3000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:bob",
     "Idempotency-Key": "K1"
    },
    "status": 201,
    "expect": {
     "id": "ch_5",
     "amount": 3000
    }
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 5,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice",
     "Idempotency-Key": ""
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 0,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 500.0,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": "x",
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 10,
     "currency": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 10,
     "currency": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 10,
     "currency": "xyz"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 2000,
     "currency": "usd"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/stripe/charges",
    "json": {
     "amount": 0,
     "currency": "usd"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=1000",
    "json": {
     "type": "payment_succeeded"
    },
    "headers": {
     "Stripe-Signature": "t=1000,v1=ae8b1bac46e4eecdb3d6f4e8fc7859a9e96aaee141bb95aba75dcb2c47385266"
    },
    "status": 200,
    "expect": {
     "received": true
    }
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=1000",
    "json": {
     "type": "payment_TAMPERED"
    },
    "headers": {
     "Stripe-Signature": "t=1000,v1=ae8b1bac46e4eecdb3d6f4e8fc7859a9e96aaee141bb95aba75dcb2c47385266"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=1000",
    "json": {
     "type": "payment_succeeded"
    },
    "headers": {
     "Stripe-Signature": "t=1000,v1=0000000000000000000000000000000000000000000000000000000000000000"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=99999",
    "json": {
     "type": "payment_succeeded"
    },
    "headers": {
     "Stripe-Signature": "t=1000,v1=ae8b1bac46e4eecdb3d6f4e8fc7859a9e96aaee141bb95aba75dcb2c47385266"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=1000",
    "json": {
     "type": "payment_succeeded"
    },
    "headers": {
     "Stripe-Signature": "totally-garbage"
    },
    "status": 400
   },
   {
    "method": "POST",
    "path": "/stripe/webhook?now=1000",
    "json": {
     "type": "payment_succeeded"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "teams",
  "cases": [
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "teamco"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "slug": "teamco",
     "owner": "alice"
    }
   },
   {
    "method": "POST",
    "path": "/orgs/teamco/transfer",
    "json": {
     "owner": "bob"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "slug": "teamco",
     "owner": "bob"
    }
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco",
     "name": "platform"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "org": "teamco",
     "name": "platform",
     "members": []
    }
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco",
     "name": "growth"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "org": "teamco",
     "name": "growth"
    }
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco",
     "name": "outsider"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco",
     "name": "anon"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "ghostorg",
     "name": "phantom"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "alice",
     "role": "lead"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "members": [
      {
       "handle": "alice",
       "role": "lead"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "zoe",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "members": [
      {
       "handle": "alice",
       "role": "lead"
      },
      {
       "handle": "zoe",
       "role": "member"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "alice",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "members": [
      {
       "handle": "alice",
       "role": "member"
      },
      {
       "handle": "zoe",
       "role": "member"
      }
     ]
    }
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "carol",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/teams/999999/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/teams/abc/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/teams/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "org": "teamco",
     "members": [
      {
       "handle": "alice",
       "role": "member"
      },
      {
       "handle": "zoe",
       "role": "member"
      }
     ]
    }
   },
   {
    "method": "GET",
    "path": "/teams/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "org": "teamco",
     "name": "platform"
    }
   },
   {
    "method": "GET",
    "path": "/teams/1",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/teams/1",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/teams/1/members/alice",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "members": [
      {
       "handle": "zoe",
       "role": "member"
      }
     ]
    }
   },
   {
    "method": "DELETE",
    "path": "/teams/1/members/alice",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "members": [
      {
       "handle": "zoe",
       "role": "member"
      }
     ]
    }
   },
   {
    "method": "DELETE",
    "path": "/teams/1/members/zoe",
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 403
   },
   {
    "method": "DELETE",
    "path": "/teams/1/members/zoe",
    "status": 401
   },
   {
    "method": "DELETE",
    "path": "/teams/999999/members/x",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/teams/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/teams/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "name": "no-org"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "",
     "name": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "teamco",
     "name": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "x"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "role": "lead"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "",
     "role": "lead"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "DELETE",
    "path": "/teams/1/members/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/orgs",
    "json": {
     "slug": "globex"
    },
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 201,
    "expect": {
     "slug": "globex",
     "owner": "dave"
    }
   },
   {
    "method": "POST",
    "path": "/teams",
    "json": {
     "org": "globex",
     "name": "ops"
    },
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "org": "globex"
    }
   },
   {
    "method": "POST",
    "path": "/teams/3/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/teams/1/members",
    "json": {
     "handle": "x",
     "role": "member"
    },
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 403
   },
   {
    "method": "GET",
    "path": "/teams/3",
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 200,
    "expect": {
     "org": "globex",
     "name": "ops"
    }
   },
   {
    "method": "GET",
    "path": "/teams/3",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/teams/1",
    "headers": {
     "Authorization": "Bearer test:dave"
    },
    "status": 404
   }
  ]
 },
 {
  "domain": "tenancy",
  "cases": [
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": "alpha"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "tenant": "alice",
     "body": "alpha"
    }
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": "beta"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "tenant": "bob",
     "body": "beta"
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "tenant": "alice",
     "body": "alpha"
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/1",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/2",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/999999",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": "gamma"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 3,
     "tenant": "alice",
     "body": "gamma"
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "tenant": "alice",
       "body": "alpha"
      },
      {
       "id": 3,
       "tenant": "alice",
       "body": "gamma"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 2,
       "tenant": "bob",
       "body": "beta"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?limit=1",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 1,
       "tenant": "alice",
       "body": "alpha"
      }
     ],
     "next_cursor": "MQ"
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?limit=1&cursor=MQ",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "results": [
      {
       "id": 3,
       "tenant": "alice",
       "body": "gamma"
      }
     ],
     "next_cursor": null
    }
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?cursor=MDU",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?cursor=MQ%3D%3D",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?limit=0",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/tenancy/notes?limit=abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": "x"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/tenancy/notes",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/1",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/tenancy/notes",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "GET",
    "path": "/tenancy/notes",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {
     "body": 7
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/tenancy/notes",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "GET",
    "path": "/tenancy/notes/abc",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   }
  ]
 },
 {
  "domain": "users",
  "cases": [
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "alice",
     "display_name": "Alice A"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": 1,
     "handle": "alice",
     "display_name": "Alice A",
     "status": "active"
    }
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "alice",
     "display_name": "Imposter"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 409
   },
   {
    "method": "GET",
    "path": "/users/alice",
    "headers": {
     "Authorization": "Bearer test:reader"
    },
    "status": 200,
    "expect": {
     "id": 1,
     "handle": "alice",
     "display_name": "Alice A",
     "status": "active"
    }
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "bob",
     "display_name": "Bob B"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": 2,
     "handle": "bob"
    }
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "handle": "alice",
     "status": "deactivated"
    }
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "status": "deactivated"
    }
   },
   {
    "method": "GET",
    "path": "/users/alice",
    "headers": {
     "Authorization": "Bearer test:reader"
    },
    "status": 200,
    "expect": {
     "status": "deactivated"
    }
   },
   {
    "method": "GET",
    "path": "/users/ghost",
    "headers": {
     "Authorization": "Bearer test:reader"
    },
    "status": 404
   },
   {
    "method": "POST",
    "path": "/users/ghost/deactivate",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 404
   },
   {
    "method": "GET",
    "path": "/users/p%1Fq",
    "headers": {
     "Authorization": "Bearer test:reader"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "display_name": "No Handle"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "",
     "display_name": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": 7,
     "display_name": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "carol"
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "carol",
     "display_name": ""
    },
    "headers": {
     "Authorization": "Bearer test:carol"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "alice",
     "display_name": "Alice A"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "alice",
     "display_name": "Alice A"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {},
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users",
    "json": {
     "handle": "alice",
     "display_name": "Squatter"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/users/alice/deactivate",
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/users/bob/deactivate",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 200,
    "expect": {
     "handle": "bob",
     "status": "deactivated"
    }
   },
   {
    "method": "GET",
    "path": "/users/alice",
    "status": 401
   },
   {
    "method": "GET",
    "path": "/users/alice",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "vectorstore",
  "cases": [
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d1",
     "text": "the quick brown fox"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "d1",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d2",
     "text": "lazy dogs sleep all day"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "d2",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "the quick brown fox"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1"
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "lazy dogs sleep all day",
     "k": 1
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d2"
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d1",
     "text": "completely different now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "d1",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "completely different now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1"
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "text": "no id"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "",
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": 7,
     "text": "x"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d9"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d9",
     "text": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {},
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": ""
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "x",
     "k": 0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "x",
     "k": 2.0
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "x",
     "k": "many"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "completely different now"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": null,
     "hits": []
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "b1",
     "text": "bob's private corpus"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": "b1",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "bob's private corpus"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "b1"
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "completely different now"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "b1"
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "completely different now"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "d1"
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "shared",
     "text": "alpha clobber payload one"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 201,
    "expect": {
     "id": "shared",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "shared",
     "text": "beta clobber payload two"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 201,
    "expect": {
     "id": "shared",
     "indexed": true
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "alpha clobber payload one"
    },
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 200,
    "expect": {
     "top": "shared"
    }
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "beta clobber payload two"
    },
    "headers": {
     "Authorization": "Bearer test:bob"
    },
    "status": 200,
    "expect": {
     "top": "shared"
    }
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d1",
     "text": "the quick brown fox"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d1",
     "text": "the quick brown fox"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "d1",
     "text": "the quick brown fox"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors",
    "json": {
     "id": "",
     "text": "x"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "the quick brown fox"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "the quick brown fox"
    },
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": "the quick brown fox"
    },
    "headers": {
     "Authorization": "test:alice"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/vectors/query",
    "json": {
     "query": ""
    },
    "status": 401
   }
  ]
 },
 {
  "domain": "webhooks",
  "cases": [
   {
    "method": "POST",
    "path": "/webhooks/send?payload=hello&now=1000",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 201,
    "expect": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,8lqOZj/heprTfB0FfT9CkaLbP8zi2OiioCncHVBtA14="
    }
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,8lqOZj/heprTfB0FfT9CkaLbP8zi2OiioCncHVBtA14="
    },
    "status": 200,
    "expect": {
     "valid": true,
     "duplicate": false
    }
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,8lqOZj/heprTfB0FfT9CkaLbP8zi2OiioCncHVBtA14="
    },
    "status": 200,
    "expect": {
     "valid": true,
     "duplicate": true
    }
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,AAAAOZj/heprTfB0FfT9CkaLbP8zi2OiioCncHVBtA14="
    },
    "status": 200,
    "expect": {
     "valid": false
    }
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=99999",
    "json": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,8lqOZj/heprTfB0FfT9CkaLbP8zi2OiioCncHVBtA14="
    },
    "status": 200,
    "expect": {
     "valid": false
    }
   },
   {
    "method": "POST",
    "path": "/webhooks/send",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=",
    "headers": {
     "Authorization": "Bearer test:root"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=hello&now=1000",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=hello&now=1000",
    "headers": {
     "Authorization": "Bearer nosuchtoken"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=hello&now=1000",
    "headers": {
     "Authorization": "test:root"
    },
    "status": 401
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=hello&now=1000",
    "headers": {
     "Authorization": "Bearer test:alice"
    },
    "status": 403
   },
   {
    "method": "POST",
    "path": "/webhooks/send",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/webhooks/send?payload=",
    "status": 401
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": 1000,
     "payload": "hello"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": "1000",
     "payload": "hello",
     "signature": "v1,x"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": "msg_1",
     "timestamp": 1000.0,
     "payload": "hello",
     "signature": "v1,x"
    },
    "status": 422
   },
   {
    "method": "POST",
    "path": "/webhooks/verify?now=1000",
    "json": {
     "id": 7,
     "timestamp": 1000,
     "payload": "hello",
     "signature": "v1,x"
    },
    "status": 422
   }
  ]
 }
]
""")

@pytest.fixture(scope="session")
def client():
    # ONE TestClient context = a single event loop for the whole suite (the same pattern the invariant tests use).
    # A module-level client with no `with` makes starlette spin up + tear down an anyio portal PER REQUEST; on
    # Windows that portal teardown races the ProactorEventLoop self-socket (an `_ssock` AttributeError that surfaces
    # as a spurious 500 under load). Entering the context once removes the churn — deterministic on every OS.
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.mark.parametrize("group", GROUPS, ids=[g["domain"] for g in GROUPS])
def test_domain(group, client):
    for case in group["cases"]:
        body = json.dumps(case["json"], separators=(",", ":")) if "json" in case else None
        headers = {"Content-Type": "application/json"} if body else {}
        headers.update(case.get("headers") or {})
        resp = client.request(case["method"], case["path"], content=body, headers=headers)
        where = f"{group['domain']}: {case['method']} {case['path']}"
        assert resp.status_code == case["status"], f"{where}: status {resp.status_code}, want {case['status']} ({resp.text[:200]})"
        if case.get("expect") is not None:
            got = resp.json()
            for k, v in case["expect"].items():
                assert k in got, f"{where}: body[{k!r}] missing"
                assert got[k] == v, f"{where}: body[{k!r}] = {got[k]!r}, want {v!r}"
