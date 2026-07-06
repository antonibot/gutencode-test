// Package app is the HTTP server wiring: the route table for this service. Domains own their
// handlers; core.Wrap adds request-id/logging/recover and core.Fallback returns problem+json
// 404 (unknown route) or 405 (known path, wrong method).
package app

import (
	"net/http"

	"app/internal/core"
	"app/internal/domains/admin"
	"app/internal/domains/agent"
	"app/internal/domains/ai_memory"
	"app/internal/domains/ai_provider"
	"app/internal/domains/ai_tools"
	"app/internal/domains/ai_workflow"
	"app/internal/domains/api_keys"
	"app/internal/domains/audit_log"
	"app/internal/domains/auth"
	"app/internal/domains/billing"
	"app/internal/domains/chat_threads"
	"app/internal/domains/crew"
	"app/internal/domains/email_outbox"
	"app/internal/domains/evals"
	"app/internal/domains/feature_flags"
	"app/internal/domains/file_store"
	"app/internal/domains/health"
	"app/internal/domains/idempotency"
	"app/internal/domains/invitations"
	"app/internal/domains/invoices"
	"app/internal/domains/job_queue"
	"app/internal/domains/ledger"
	"app/internal/domains/llm_usage"
	"app/internal/domains/notifications"
	"app/internal/domains/oauth"
	"app/internal/domains/orgs"
	"app/internal/domains/payments"
	"app/internal/domains/prompt_registry"
	"app/internal/domains/rag"
	"app/internal/domains/ratelimit"
	"app/internal/domains/rbac"
	"app/internal/domains/records"
	"app/internal/domains/reporting"
	"app/internal/domains/search"
	"app/internal/domains/secrets_vault"
	"app/internal/domains/settings"
	"app/internal/domains/storage"
	"app/internal/domains/stripe"
	"app/internal/domains/teams"
	"app/internal/domains/tenancy"
	"app/internal/domains/users"
	"app/internal/domains/vectorstore"
	"app/internal/domains/webhooks"
)

func NewServer() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/actions", admin.AdminRecord)
	mux.HandleFunc("GET /admin/actions", admin.AdminList)
	mux.HandleFunc("GET /admin/actions/{action_id}", admin.AdminGet)
	mux.HandleFunc("POST /agents/", agent.AgentCreate)
	mux.HandleFunc("POST /agents/{agent_id}/sessions", agent.AgentCreateSession)
	mux.HandleFunc("POST /agents/{agent_id}/sessions/{session_id}/run", agent.AgentRun)
	mux.HandleFunc("GET /agents/{agent_id}/sessions/{session_id}/messages", agent.AgentMessages)
	mux.HandleFunc("POST /ai_memory/memories", ai_memory.AiMemoryAdd)
	mux.HandleFunc("GET /ai_memory/memories", ai_memory.AiMemoryList)
	mux.HandleFunc("GET /ai_memory/memories/{id}", ai_memory.AiMemoryGet)
	mux.HandleFunc("DELETE /ai_memory/memories/{id}", ai_memory.AiMemoryForget)
	mux.HandleFunc("DELETE /ai_memory/memories", ai_memory.AiMemoryForgetScope)
	mux.HandleFunc("POST /ai/complete", ai_provider.AiProviderComplete)
	mux.HandleFunc("GET /ai/usage", ai_provider.AiProviderUsage)
	mux.HandleFunc("GET /tools", ai_tools.AiToolsList)
	mux.HandleFunc("POST /tools/{tool_name}/invoke", ai_tools.AiToolsInvoke)
	mux.HandleFunc("POST /workflows", ai_workflow.AiWorkflowCreate)
	mux.HandleFunc("POST /workflows/{workflow_id}/run", ai_workflow.AiWorkflowRun)
	mux.HandleFunc("POST /api_keys", api_keys.ApiKeysCreate)
	mux.HandleFunc("GET /api_keys", api_keys.ApiKeysList)
	mux.HandleFunc("GET /api_keys/{key_id}", api_keys.ApiKeysGet)
	mux.HandleFunc("POST /api_keys/verify", api_keys.ApiKeysVerify)
	mux.HandleFunc("POST /api_keys/{key_id}/rotate", api_keys.ApiKeysRotate)
	mux.HandleFunc("POST /api_keys/{key_id}/revoke", api_keys.ApiKeysRevoke)
	mux.HandleFunc("POST /audit_log/events", audit_log.AuditLogAppend)
	mux.HandleFunc("GET /audit_log/events", audit_log.AuditLogList)
	mux.HandleFunc("GET /audit_log/verify", audit_log.AuditLogVerify)
	mux.HandleFunc("POST /auth/register", auth.AuthRegister)
	mux.HandleFunc("POST /auth/login", auth.AuthLogin)
	mux.HandleFunc("POST /auth/refresh", auth.AuthRefresh)
	mux.HandleFunc("POST /auth/logout", auth.AuthLogout)
	mux.HandleFunc("POST /auth/password/reset/request", auth.AuthResetRequest)
	mux.HandleFunc("POST /auth/password/reset/confirm", auth.AuthResetConfirm)
	mux.HandleFunc("POST /auth/verify/request", auth.AuthVerifyRequest)
	mux.HandleFunc("POST /auth/verify/confirm", auth.AuthVerifyConfirm)
	mux.HandleFunc("GET /auth/me", auth.AuthMe)
	mux.HandleFunc("POST /billing/subscriptions", billing.BillingSubscribe)
	mux.HandleFunc("GET /billing/subscriptions/{sub_id}", billing.BillingGet)
	mux.HandleFunc("POST /billing/subscriptions/{sub_id}/cancel", billing.BillingCancel)
	mux.HandleFunc("POST /chat_threads", chat_threads.ChatThreadsCreate)
	mux.HandleFunc("GET /chat_threads", chat_threads.ChatThreadsList)
	mux.HandleFunc("GET /chat_threads/{id}", chat_threads.ChatThreadsGet)
	mux.HandleFunc("PATCH /chat_threads/{id}", chat_threads.ChatThreadsUpdate)
	mux.HandleFunc("DELETE /chat_threads/{id}", chat_threads.ChatThreadsDelete)
	mux.HandleFunc("POST /chat_threads/{id}/messages", chat_threads.ChatThreadsAppend)
	mux.HandleFunc("GET /chat_threads/{id}/messages", chat_threads.ChatThreadsMessages)
	mux.HandleFunc("POST /crews", crew.CrewCreate)
	mux.HandleFunc("POST /crews/{crew_id}/run", crew.CrewRun)
	mux.HandleFunc("POST /email_outbox/messages", email_outbox.EmailOutboxSend)
	mux.HandleFunc("GET /email_outbox/messages", email_outbox.EmailOutboxList)
	mux.HandleFunc("GET /email_outbox/messages/{message_id}", email_outbox.EmailOutboxGet)
	mux.HandleFunc("POST /evals/suites", evals.EvalsCreateSuite)
	mux.HandleFunc("GET /evals/suites", evals.EvalsListSuites)
	mux.HandleFunc("GET /evals/suites/{name}", evals.EvalsGetSuite)
	mux.HandleFunc("POST /evals/suites/{name}/score", evals.EvalsScore)
	mux.HandleFunc("POST /feature_flags", feature_flags.FeatureFlagsCreate)
	mux.HandleFunc("GET /feature_flags/{key}", feature_flags.FeatureFlagsGet)
	mux.HandleFunc("PUT /feature_flags/{key}", feature_flags.FeatureFlagsSetRollout)
	mux.HandleFunc("GET /feature_flags/{key}/evaluate", feature_flags.FeatureFlagsEvaluate)
	mux.HandleFunc("POST /file_store", file_store.FileStorePut)
	mux.HandleFunc("GET /file_store", file_store.FileStoreList)
	mux.HandleFunc("GET /file_store/{file_key}/meta", file_store.FileStoreMeta)
	mux.HandleFunc("GET /file_store/{file_key}", file_store.FileStoreGet)
	mux.HandleFunc("DELETE /file_store/{file_key}", file_store.FileStoreDelete)
	mux.HandleFunc("GET /health", health.HealthCheck)
	mux.HandleFunc("POST /idempotency/payments", idempotency.IdempotencyPay)
	mux.HandleFunc("POST /invitations", invitations.InvitationsCreate)
	mux.HandleFunc("POST /invitations/{token}/accept", invitations.InvitationsAccept)
	mux.HandleFunc("POST /invoices", invoices.InvoicesCreate)
	mux.HandleFunc("GET /invoices", invoices.InvoicesList)
	mux.HandleFunc("GET /invoices/{invoice_id}", invoices.InvoicesGet)
	mux.HandleFunc("PATCH /invoices/{invoice_id}", invoices.InvoicesUpdate)
	mux.HandleFunc("POST /invoices/{invoice_id}/finalize", invoices.InvoicesFinalize)
	mux.HandleFunc("POST /invoices/{invoice_id}/pay", invoices.InvoicesPay)
	mux.HandleFunc("POST /invoices/{invoice_id}/void", invoices.InvoicesVoid)
	mux.HandleFunc("POST /invoices/{invoice_id}/mark_uncollectible", invoices.InvoicesMarkUncollectible)
	mux.HandleFunc("POST /job_queue", job_queue.JobsEnqueue)
	mux.HandleFunc("POST /job_queue/claim", job_queue.JobsClaim)
	mux.HandleFunc("POST /job_queue/{job_id}/complete", job_queue.JobsComplete)
	mux.HandleFunc("POST /job_queue/{job_id}/fail", job_queue.JobsFail)
	mux.HandleFunc("GET /job_queue", job_queue.JobsList)
	mux.HandleFunc("GET /job_queue/{job_id}", job_queue.JobsGet)
	mux.HandleFunc("POST /ledger/transactions", ledger.LedgerPost)
	mux.HandleFunc("GET /ledger/accounts/{account_id}/balance", ledger.LedgerBalance)
	mux.HandleFunc("POST /llm_usage/events", llm_usage.LlmUsageRecord)
	mux.HandleFunc("GET /llm_usage/summary", llm_usage.LlmUsageSummary)
	mux.HandleFunc("GET /llm_usage/events", llm_usage.LlmUsageEvents)
	mux.HandleFunc("POST /notifications", notifications.NotificationsSend)
	mux.HandleFunc("GET /notifications", notifications.NotificationsList)
	mux.HandleFunc("POST /notifications/{note_id}/read", notifications.NotificationsRead)
	mux.HandleFunc("POST /oauth/authorize", oauth.OauthAuthorize)
	mux.HandleFunc("POST /oauth/callback", oauth.OauthCallback)
	mux.HandleFunc("POST /orgs", orgs.OrgsCreate)
	mux.HandleFunc("GET /orgs", orgs.OrgsListMine)
	mux.HandleFunc("GET /orgs/{slug}", orgs.OrgsGet)
	mux.HandleFunc("POST /orgs/{slug}/transfer", orgs.OrgsTransfer)
	mux.HandleFunc("POST /orgs/{slug}/archive", orgs.OrgsArchive)
	mux.HandleFunc("POST /orgs/{slug}/members", orgs.OrgsAddMember)
	mux.HandleFunc("GET /orgs/{slug}/members", orgs.OrgsListMembers)
	mux.HandleFunc("POST /orgs/{slug}/members/accept", orgs.OrgsAccept)
	mux.HandleFunc("DELETE /orgs/{slug}/members/{handle}", orgs.OrgsRemoveMember)
	mux.HandleFunc("GET /orgs/{slug}/invitations", orgs.OrgsListInvites)
	mux.HandleFunc("POST /orgs/{slug}/leave", orgs.OrgsLeave)
	mux.HandleFunc("POST /payments", payments.PaymentsAuthorize)
	mux.HandleFunc("GET /payments", payments.PaymentsList)
	mux.HandleFunc("GET /payments/{payment_id}", payments.PaymentsGet)
	mux.HandleFunc("POST /payments/{payment_id}/capture", payments.PaymentsCapture)
	mux.HandleFunc("POST /payments/{payment_id}/void", payments.PaymentsVoid)
	mux.HandleFunc("POST /payments/{payment_id}/refund", payments.PaymentsRefund)
	mux.HandleFunc("POST /prompt_registry/prompts/{name}/versions", prompt_registry.PromptRegistryCreateVersion)
	mux.HandleFunc("GET /prompt_registry/prompts/{name}/versions/{version}", prompt_registry.PromptRegistryGetVersion)
	mux.HandleFunc("GET /prompt_registry/prompts", prompt_registry.PromptRegistryListPrompts)
	mux.HandleFunc("GET /prompt_registry/prompts/{name}", prompt_registry.PromptRegistryGetPrompt)
	mux.HandleFunc("PUT /prompt_registry/prompts/{name}/labels/{label}", prompt_registry.PromptRegistrySetLabel)
	mux.HandleFunc("POST /prompt_registry/prompts/{name}/render", prompt_registry.PromptRegistryRender)
	mux.HandleFunc("POST /rag/documents", rag.RagIngest)
	mux.HandleFunc("POST /rag/query", rag.RagQuery)
	mux.HandleFunc("POST /ratelimit/check", ratelimit.RatelimitCheck)
	mux.HandleFunc("POST /rbac/roles", rbac.RbacAssign)
	mux.HandleFunc("GET /rbac/can", rbac.RbacCan)
	mux.HandleFunc("POST /rbac/relations", rbac.RbacGrant)
	mux.HandleFunc("GET /rbac/check", rbac.RbacCheck)
	mux.HandleFunc("DELETE /rbac/roles", rbac.RbacRevokeRole)
	mux.HandleFunc("DELETE /rbac/relations", rbac.RbacRevokeRelation)
	mux.HandleFunc("GET /rbac/roles", rbac.RbacListRoles)
	mux.HandleFunc("GET /rbac/relations", rbac.RbacListRelations)
	mux.HandleFunc("GET /rbac/decisions", rbac.RbacListDecisions)
	mux.HandleFunc("POST /records", records.RecordsCreate)
	mux.HandleFunc("GET /records", records.RecordsList)
	mux.HandleFunc("GET /records/{record_id}", records.RecordsGet)
	mux.HandleFunc("PATCH /records/{record_id}", records.RecordsUpdate)
	mux.HandleFunc("DELETE /records/{record_id}", records.RecordsDelete)
	mux.HandleFunc("POST /reporting/facts", reporting.ReportingFactsCreate)
	mux.HandleFunc("GET /reporting/facts", reporting.ReportingFactsList)
	mux.HandleFunc("POST /reporting/query", reporting.ReportingQuery)
	mux.HandleFunc("DELETE /reporting/facts", reporting.ReportingFactsDrain)
	mux.HandleFunc("POST /search/index", search.SearchIndex)
	mux.HandleFunc("GET /search/query", search.SearchQuery)
	mux.HandleFunc("GET /secrets_vault", secrets_vault.SecretsVaultList)
	mux.HandleFunc("GET /secrets_vault/access", secrets_vault.SecretsVaultAccessLog)
	mux.HandleFunc("PUT /secrets_vault/{name}", secrets_vault.SecretsVaultPut)
	mux.HandleFunc("GET /secrets_vault/{name}", secrets_vault.SecretsVaultGet)
	mux.HandleFunc("POST /secrets_vault/{name}/reveal", secrets_vault.SecretsVaultReveal)
	mux.HandleFunc("POST /secrets_vault/{name}/destroy", secrets_vault.SecretsVaultDestroy)
	mux.HandleFunc("POST /secrets_vault/{name}/disable", secrets_vault.SecretsVaultDisable)
	mux.HandleFunc("POST /secrets_vault/{name}/enable", secrets_vault.SecretsVaultEnable)
	mux.HandleFunc("GET /settings", settings.SettingsList)
	mux.HandleFunc("GET /settings/{key}", settings.SettingsGet)
	mux.HandleFunc("PUT /settings/{key}", settings.SettingsPut)
	mux.HandleFunc("POST /storage", storage.StoragePut)
	mux.HandleFunc("GET /storage", storage.StorageList)
	mux.HandleFunc("GET /storage/{object_key}", storage.StorageGet)
	mux.HandleFunc("DELETE /storage/{object_key}", storage.StorageDelete)
	mux.HandleFunc("POST /stripe/charges", stripe.StripeCharge)
	mux.HandleFunc("POST /stripe/webhook", stripe.StripeWebhook)
	mux.HandleFunc("POST /teams", teams.TeamsCreate)
	mux.HandleFunc("GET /teams/{team_id}", teams.TeamsGet)
	mux.HandleFunc("POST /teams/{team_id}/members", teams.TeamsAddMember)
	mux.HandleFunc("DELETE /teams/{team_id}/members/{handle}", teams.TeamsRemoveMember)
	mux.HandleFunc("POST /tenancy/notes", tenancy.TenancyCreate)
	mux.HandleFunc("GET /tenancy/notes", tenancy.TenancyList)
	mux.HandleFunc("GET /tenancy/notes/{note_id}", tenancy.TenancyGet)
	mux.HandleFunc("POST /users", users.UsersCreate)
	mux.HandleFunc("GET /users/{handle}", users.UsersGet)
	mux.HandleFunc("POST /users/{handle}/deactivate", users.UsersDeactivate)
	mux.HandleFunc("POST /vectors", vectorstore.VectorstoreIndex)
	mux.HandleFunc("POST /vectors/query", vectorstore.VectorstoreQuery)
	mux.HandleFunc("POST /webhooks/send", webhooks.WebhookSend)
	mux.HandleFunc("POST /webhooks/verify", webhooks.WebhookVerify)
	mux.HandleFunc("/", core.Fallback([]string{"POST /admin/actions", "GET /admin/actions", "GET /admin/actions/{action_id}", "POST /agents/", "POST /agents/{agent_id}/sessions", "POST /agents/{agent_id}/sessions/{session_id}/run", "GET /agents/{agent_id}/sessions/{session_id}/messages", "POST /ai_memory/memories", "GET /ai_memory/memories", "GET /ai_memory/memories/{id}", "DELETE /ai_memory/memories/{id}", "DELETE /ai_memory/memories", "POST /ai/complete", "GET /ai/usage", "GET /tools", "POST /tools/{tool_name}/invoke", "POST /workflows", "POST /workflows/{workflow_id}/run", "POST /api_keys", "GET /api_keys", "GET /api_keys/{key_id}", "POST /api_keys/verify", "POST /api_keys/{key_id}/rotate", "POST /api_keys/{key_id}/revoke", "POST /audit_log/events", "GET /audit_log/events", "GET /audit_log/verify", "POST /auth/register", "POST /auth/login", "POST /auth/refresh", "POST /auth/logout", "POST /auth/password/reset/request", "POST /auth/password/reset/confirm", "POST /auth/verify/request", "POST /auth/verify/confirm", "GET /auth/me", "POST /billing/subscriptions", "GET /billing/subscriptions/{sub_id}", "POST /billing/subscriptions/{sub_id}/cancel", "POST /chat_threads", "GET /chat_threads", "GET /chat_threads/{id}", "PATCH /chat_threads/{id}", "DELETE /chat_threads/{id}", "POST /chat_threads/{id}/messages", "GET /chat_threads/{id}/messages", "POST /crews", "POST /crews/{crew_id}/run", "POST /email_outbox/messages", "GET /email_outbox/messages", "GET /email_outbox/messages/{message_id}", "POST /evals/suites", "GET /evals/suites", "GET /evals/suites/{name}", "POST /evals/suites/{name}/score", "POST /feature_flags", "GET /feature_flags/{key}", "PUT /feature_flags/{key}", "GET /feature_flags/{key}/evaluate", "POST /file_store", "GET /file_store", "GET /file_store/{file_key}/meta", "GET /file_store/{file_key}", "DELETE /file_store/{file_key}", "GET /health", "POST /idempotency/payments", "POST /invitations", "POST /invitations/{token}/accept", "POST /invoices", "GET /invoices", "GET /invoices/{invoice_id}", "PATCH /invoices/{invoice_id}", "POST /invoices/{invoice_id}/finalize", "POST /invoices/{invoice_id}/pay", "POST /invoices/{invoice_id}/void", "POST /invoices/{invoice_id}/mark_uncollectible", "POST /job_queue", "POST /job_queue/claim", "POST /job_queue/{job_id}/complete", "POST /job_queue/{job_id}/fail", "GET /job_queue", "GET /job_queue/{job_id}", "POST /ledger/transactions", "GET /ledger/accounts/{account_id}/balance", "POST /llm_usage/events", "GET /llm_usage/summary", "GET /llm_usage/events", "POST /notifications", "GET /notifications", "POST /notifications/{note_id}/read", "POST /oauth/authorize", "POST /oauth/callback", "POST /orgs", "GET /orgs", "GET /orgs/{slug}", "POST /orgs/{slug}/transfer", "POST /orgs/{slug}/archive", "POST /orgs/{slug}/members", "GET /orgs/{slug}/members", "POST /orgs/{slug}/members/accept", "DELETE /orgs/{slug}/members/{handle}", "GET /orgs/{slug}/invitations", "POST /orgs/{slug}/leave", "POST /payments", "GET /payments", "GET /payments/{payment_id}", "POST /payments/{payment_id}/capture", "POST /payments/{payment_id}/void", "POST /payments/{payment_id}/refund", "POST /prompt_registry/prompts/{name}/versions", "GET /prompt_registry/prompts/{name}/versions/{version}", "GET /prompt_registry/prompts", "GET /prompt_registry/prompts/{name}", "PUT /prompt_registry/prompts/{name}/labels/{label}", "POST /prompt_registry/prompts/{name}/render", "POST /rag/documents", "POST /rag/query", "POST /ratelimit/check", "POST /rbac/roles", "GET /rbac/can", "POST /rbac/relations", "GET /rbac/check", "DELETE /rbac/roles", "DELETE /rbac/relations", "GET /rbac/roles", "GET /rbac/relations", "GET /rbac/decisions", "POST /records", "GET /records", "GET /records/{record_id}", "PATCH /records/{record_id}", "DELETE /records/{record_id}", "POST /reporting/facts", "GET /reporting/facts", "POST /reporting/query", "DELETE /reporting/facts", "POST /search/index", "GET /search/query", "GET /secrets_vault", "GET /secrets_vault/access", "PUT /secrets_vault/{name}", "GET /secrets_vault/{name}", "POST /secrets_vault/{name}/reveal", "POST /secrets_vault/{name}/destroy", "POST /secrets_vault/{name}/disable", "POST /secrets_vault/{name}/enable", "GET /settings", "GET /settings/{key}", "PUT /settings/{key}", "POST /storage", "GET /storage", "GET /storage/{object_key}", "DELETE /storage/{object_key}", "POST /stripe/charges", "POST /stripe/webhook", "POST /teams", "GET /teams/{team_id}", "POST /teams/{team_id}/members", "DELETE /teams/{team_id}/members/{handle}", "POST /tenancy/notes", "GET /tenancy/notes", "GET /tenancy/notes/{note_id}", "POST /users", "GET /users/{handle}", "POST /users/{handle}/deactivate", "POST /vectors", "POST /vectors/query", "POST /webhooks/send", "POST /webhooks/verify"}))
	return core.Wrap(mux)
}
