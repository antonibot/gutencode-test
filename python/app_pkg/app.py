"""The HTTP application wiring. install_runtime wires the one RFC 9457 error envelope (404/422/500),
the request-id + access-log middleware, and the body-size cap; domains register their own routers."""
from fastapi import FastAPI

from .core.errors import install_runtime
from .domains.admin import router as admin_router
from .domains.agent import router as agent_router
from .domains.ai_memory import router as ai_memory_router
from .domains.ai_provider import router as ai_provider_router
from .domains.ai_tools import router as ai_tools_router
from .domains.ai_workflow import router as ai_workflow_router
from .domains.api_keys import router as api_keys_router
from .domains.audit_log import router as audit_log_router
from .domains.auth import router as auth_router
from .domains.billing import router as billing_router
from .domains.chat_threads import router as chat_threads_router
from .domains.crew import router as crew_router
from .domains.email_outbox import router as email_outbox_router
from .domains.evals import router as evals_router
from .domains.feature_flags import router as feature_flags_router
from .domains.file_store import router as file_store_router
from .domains.health import router as health_router
from .domains.idempotency import router as idempotency_router
from .domains.invitations import router as invitations_router
from .domains.invoices import router as invoices_router
from .domains.job_queue import router as job_queue_router
from .domains.ledger import router as ledger_router
from .domains.llm_usage import router as llm_usage_router
from .domains.notifications import router as notifications_router
from .domains.oauth import router as oauth_router
from .domains.orgs import router as orgs_router
from .domains.payments import router as payments_router
from .domains.prompt_registry import router as prompt_registry_router
from .domains.rag import router as rag_router
from .domains.ratelimit import router as ratelimit_router
from .domains.rbac import router as rbac_router
from .domains.records import router as records_router
from .domains.reporting import router as reporting_router
from .domains.search import router as search_router
from .domains.secrets_vault import router as secrets_vault_router
from .domains.settings import router as settings_router
from .domains.storage import router as storage_router
from .domains.stripe import router as stripe_router
from .domains.teams import router as teams_router
from .domains.tenancy import router as tenancy_router
from .domains.users import router as users_router
from .domains.vectorstore import router as vectorstore_router
from .domains.webhooks import router as webhooks_router


def create_app() -> FastAPI:
    app = FastAPI(title="_export_spine")
    install_runtime(app)
    app.include_router(admin_router)
    app.include_router(agent_router)
    app.include_router(ai_memory_router)
    app.include_router(ai_provider_router)
    app.include_router(ai_tools_router)
    app.include_router(ai_workflow_router)
    app.include_router(api_keys_router)
    app.include_router(audit_log_router)
    app.include_router(auth_router)
    app.include_router(billing_router)
    app.include_router(chat_threads_router)
    app.include_router(crew_router)
    app.include_router(email_outbox_router)
    app.include_router(evals_router)
    app.include_router(feature_flags_router)
    app.include_router(file_store_router)
    app.include_router(health_router)
    app.include_router(idempotency_router)
    app.include_router(invitations_router)
    app.include_router(invoices_router)
    app.include_router(job_queue_router)
    app.include_router(ledger_router)
    app.include_router(llm_usage_router)
    app.include_router(notifications_router)
    app.include_router(oauth_router)
    app.include_router(orgs_router)
    app.include_router(payments_router)
    app.include_router(prompt_registry_router)
    app.include_router(rag_router)
    app.include_router(ratelimit_router)
    app.include_router(rbac_router)
    app.include_router(records_router)
    app.include_router(reporting_router)
    app.include_router(search_router)
    app.include_router(secrets_vault_router)
    app.include_router(settings_router)
    app.include_router(storage_router)
    app.include_router(stripe_router)
    app.include_router(teams_router)
    app.include_router(tenancy_router)
    app.include_router(users_router)
    app.include_router(vectorstore_router)
    app.include_router(webhooks_router)
    return app


app = create_app()
