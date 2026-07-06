// The HTTP server wiring: the route table for this service.
import { createServer } from './core/runtime.js';
import * as admin from './domains/admin.js';
import * as agent from './domains/agent/index.js';
import * as ai_memory from './domains/ai_memory/index.js';
import * as ai_provider from './domains/ai_provider.js';
import * as ai_tools from './domains/ai_tools.js';
import * as ai_workflow from './domains/ai_workflow.js';
import * as api_keys from './domains/api_keys.js';
import * as audit_log from './domains/audit_log.js';
import * as auth from './domains/auth.js';
import * as billing from './domains/billing.js';
import * as chat_threads from './domains/chat_threads/index.js';
import * as crew from './domains/crew.js';
import * as email_outbox from './domains/email_outbox.js';
import * as evals from './domains/evals.js';
import * as feature_flags from './domains/feature_flags.js';
import * as file_store from './domains/file_store/index.js';
import * as health from './domains/health.js';
import * as idempotency from './domains/idempotency.js';
import * as invitations from './domains/invitations.js';
import * as invoices from './domains/invoices/index.js';
import * as job_queue from './domains/job_queue.js';
import * as ledger from './domains/ledger.js';
import * as llm_usage from './domains/llm_usage.js';
import * as notifications from './domains/notifications.js';
import * as oauth from './domains/oauth.js';
import * as orgs from './domains/orgs/index.js';
import * as payments from './domains/payments.js';
import * as prompt_registry from './domains/prompt_registry.js';
import * as rag from './domains/rag.js';
import * as ratelimit from './domains/ratelimit.js';
import * as rbac from './domains/rbac.js';
import * as records from './domains/records.js';
import * as reporting from './domains/reporting.js';
import * as search from './domains/search.js';
import * as secrets_vault from './domains/secrets_vault/index.js';
import * as settings from './domains/settings.js';
import * as storage from './domains/storage/index.js';
import * as stripe from './domains/stripe.js';
import * as teams from './domains/teams.js';
import * as tenancy from './domains/tenancy.js';
import * as users from './domains/users.js';
import * as vectorstore from './domains/vectorstore.js';
import * as webhooks from './domains/webhooks.js';

export const routes = [
  ["POST", "/admin/actions", admin.adminRecord],
  ["GET", "/admin/actions", admin.adminList],
  ["GET", "/admin/actions/{action_id}", admin.adminGet],
  ["POST", "/agents/", agent.agentCreate],
  ["POST", "/agents/{agent_id}/sessions", agent.agentCreateSession],
  ["POST", "/agents/{agent_id}/sessions/{session_id}/run", agent.agentRun],
  ["GET", "/agents/{agent_id}/sessions/{session_id}/messages", agent.agentMessages],
  ["POST", "/ai_memory/memories", ai_memory.aiMemoryAdd],
  ["GET", "/ai_memory/memories", ai_memory.aiMemoryList],
  ["GET", "/ai_memory/memories/{id}", ai_memory.aiMemoryGet],
  ["DELETE", "/ai_memory/memories/{id}", ai_memory.aiMemoryForget],
  ["DELETE", "/ai_memory/memories", ai_memory.aiMemoryForgetScope],
  ["POST", "/ai/complete", ai_provider.aiProviderComplete],
  ["GET", "/ai/usage", ai_provider.aiProviderUsage],
  ["GET", "/tools", ai_tools.aiToolsList],
  ["POST", "/tools/{tool_name}/invoke", ai_tools.aiToolsInvoke],
  ["POST", "/workflows", ai_workflow.aiWorkflowCreate],
  ["POST", "/workflows/{workflow_id}/run", ai_workflow.aiWorkflowRun],
  ["POST", "/api_keys", api_keys.apiKeysCreate],
  ["GET", "/api_keys", api_keys.apiKeysList],
  ["GET", "/api_keys/{key_id}", api_keys.apiKeysGet],
  ["POST", "/api_keys/verify", api_keys.apiKeysVerify],
  ["POST", "/api_keys/{key_id}/rotate", api_keys.apiKeysRotate],
  ["POST", "/api_keys/{key_id}/revoke", api_keys.apiKeysRevoke],
  ["POST", "/audit_log/events", audit_log.auditLogAppend],
  ["GET", "/audit_log/events", audit_log.auditLogList],
  ["GET", "/audit_log/verify", audit_log.auditLogVerify],
  ["POST", "/auth/register", auth.authRegister],
  ["POST", "/auth/login", auth.authLogin],
  ["POST", "/auth/refresh", auth.authRefresh],
  ["POST", "/auth/logout", auth.authLogout],
  ["POST", "/auth/password/reset/request", auth.authResetRequest],
  ["POST", "/auth/password/reset/confirm", auth.authResetConfirm],
  ["POST", "/auth/verify/request", auth.authVerifyRequest],
  ["POST", "/auth/verify/confirm", auth.authVerifyConfirm],
  ["GET", "/auth/me", auth.authMe],
  ["POST", "/billing/subscriptions", billing.billingSubscribe],
  ["GET", "/billing/subscriptions/{sub_id}", billing.billingGet],
  ["POST", "/billing/subscriptions/{sub_id}/cancel", billing.billingCancel],
  ["POST", "/chat_threads", chat_threads.chatThreadsCreate],
  ["GET", "/chat_threads", chat_threads.chatThreadsList],
  ["GET", "/chat_threads/{id}", chat_threads.chatThreadsGet],
  ["PATCH", "/chat_threads/{id}", chat_threads.chatThreadsUpdate],
  ["DELETE", "/chat_threads/{id}", chat_threads.chatThreadsDelete],
  ["POST", "/chat_threads/{id}/messages", chat_threads.chatThreadsAppend],
  ["GET", "/chat_threads/{id}/messages", chat_threads.chatThreadsMessages],
  ["POST", "/crews", crew.crewCreate],
  ["POST", "/crews/{crew_id}/run", crew.crewRun],
  ["POST", "/email_outbox/messages", email_outbox.emailOutboxSend],
  ["GET", "/email_outbox/messages", email_outbox.emailOutboxList],
  ["GET", "/email_outbox/messages/{message_id}", email_outbox.emailOutboxGet],
  ["POST", "/evals/suites", evals.evalsCreateSuite],
  ["GET", "/evals/suites", evals.evalsListSuites],
  ["GET", "/evals/suites/{name}", evals.evalsGetSuite],
  ["POST", "/evals/suites/{name}/score", evals.evalsScore],
  ["POST", "/feature_flags", feature_flags.featureFlagsCreate],
  ["GET", "/feature_flags/{key}", feature_flags.featureFlagsGet],
  ["PUT", "/feature_flags/{key}", feature_flags.featureFlagsSetRollout],
  ["GET", "/feature_flags/{key}/evaluate", feature_flags.featureFlagsEvaluate],
  ["POST", "/file_store", file_store.fileStorePut],
  ["GET", "/file_store", file_store.fileStoreList],
  ["GET", "/file_store/{file_key}/meta", file_store.fileStoreMeta],
  ["GET", "/file_store/{file_key}", file_store.fileStoreGet],
  ["DELETE", "/file_store/{file_key}", file_store.fileStoreDelete],
  ["GET", "/health", health.healthCheck],
  ["POST", "/idempotency/payments", idempotency.idempotencyPay],
  ["POST", "/invitations", invitations.invitationsCreate],
  ["POST", "/invitations/{token}/accept", invitations.invitationsAccept],
  ["POST", "/invoices", invoices.invoicesCreate],
  ["GET", "/invoices", invoices.invoicesList],
  ["GET", "/invoices/{invoice_id}", invoices.invoicesGet],
  ["PATCH", "/invoices/{invoice_id}", invoices.invoicesUpdate],
  ["POST", "/invoices/{invoice_id}/finalize", invoices.invoicesFinalize],
  ["POST", "/invoices/{invoice_id}/pay", invoices.invoicesPay],
  ["POST", "/invoices/{invoice_id}/void", invoices.invoicesVoid],
  ["POST", "/invoices/{invoice_id}/mark_uncollectible", invoices.invoicesMarkUncollectible],
  ["POST", "/job_queue", job_queue.jobsEnqueue],
  ["POST", "/job_queue/claim", job_queue.jobsClaim],
  ["POST", "/job_queue/{job_id}/complete", job_queue.jobsComplete],
  ["POST", "/job_queue/{job_id}/fail", job_queue.jobsFail],
  ["GET", "/job_queue", job_queue.jobsList],
  ["GET", "/job_queue/{job_id}", job_queue.jobsGet],
  ["POST", "/ledger/transactions", ledger.ledgerPost],
  ["GET", "/ledger/accounts/{account_id}/balance", ledger.ledgerBalance],
  ["POST", "/llm_usage/events", llm_usage.llmUsageRecord],
  ["GET", "/llm_usage/summary", llm_usage.llmUsageSummary],
  ["GET", "/llm_usage/events", llm_usage.llmUsageEvents],
  ["POST", "/notifications", notifications.notificationsSend],
  ["GET", "/notifications", notifications.notificationsList],
  ["POST", "/notifications/{note_id}/read", notifications.notificationsRead],
  ["POST", "/oauth/authorize", oauth.oauthAuthorize],
  ["POST", "/oauth/callback", oauth.oauthCallback],
  ["POST", "/orgs", orgs.orgsCreate],
  ["GET", "/orgs", orgs.orgsListMine],
  ["GET", "/orgs/{slug}", orgs.orgsGet],
  ["POST", "/orgs/{slug}/transfer", orgs.orgsTransfer],
  ["POST", "/orgs/{slug}/archive", orgs.orgsArchive],
  ["POST", "/orgs/{slug}/members", orgs.orgsAddMember],
  ["GET", "/orgs/{slug}/members", orgs.orgsListMembers],
  ["POST", "/orgs/{slug}/members/accept", orgs.orgsAccept],
  ["DELETE", "/orgs/{slug}/members/{handle}", orgs.orgsRemoveMember],
  ["GET", "/orgs/{slug}/invitations", orgs.orgsListInvites],
  ["POST", "/orgs/{slug}/leave", orgs.orgsLeave],
  ["POST", "/payments", payments.paymentsAuthorize],
  ["GET", "/payments", payments.paymentsList],
  ["GET", "/payments/{payment_id}", payments.paymentsGet],
  ["POST", "/payments/{payment_id}/capture", payments.paymentsCapture],
  ["POST", "/payments/{payment_id}/void", payments.paymentsVoid],
  ["POST", "/payments/{payment_id}/refund", payments.paymentsRefund],
  ["POST", "/prompt_registry/prompts/{name}/versions", prompt_registry.promptRegistryCreateVersion],
  ["GET", "/prompt_registry/prompts/{name}/versions/{version}", prompt_registry.promptRegistryGetVersion],
  ["GET", "/prompt_registry/prompts", prompt_registry.promptRegistryListPrompts],
  ["GET", "/prompt_registry/prompts/{name}", prompt_registry.promptRegistryGetPrompt],
  ["PUT", "/prompt_registry/prompts/{name}/labels/{label}", prompt_registry.promptRegistrySetLabel],
  ["POST", "/prompt_registry/prompts/{name}/render", prompt_registry.promptRegistryRender],
  ["POST", "/rag/documents", rag.ragIngest],
  ["POST", "/rag/query", rag.ragQuery],
  ["POST", "/ratelimit/check", ratelimit.ratelimitCheck],
  ["POST", "/rbac/roles", rbac.rbacAssign],
  ["GET", "/rbac/can", rbac.rbacCan],
  ["POST", "/rbac/relations", rbac.rbacGrant],
  ["GET", "/rbac/check", rbac.rbacCheck],
  ["DELETE", "/rbac/roles", rbac.rbacRevokeRole],
  ["DELETE", "/rbac/relations", rbac.rbacRevokeRelation],
  ["GET", "/rbac/roles", rbac.rbacListRoles],
  ["GET", "/rbac/relations", rbac.rbacListRelations],
  ["GET", "/rbac/decisions", rbac.rbacListDecisions],
  ["POST", "/records", records.recordsCreate],
  ["GET", "/records", records.recordsList],
  ["GET", "/records/{record_id}", records.recordsGet],
  ["PATCH", "/records/{record_id}", records.recordsUpdate],
  ["DELETE", "/records/{record_id}", records.recordsDelete],
  ["POST", "/reporting/facts", reporting.reportingFactsCreate],
  ["GET", "/reporting/facts", reporting.reportingFactsList],
  ["POST", "/reporting/query", reporting.reportingQuery],
  ["DELETE", "/reporting/facts", reporting.reportingFactsDrain],
  ["POST", "/search/index", search.searchIndex],
  ["GET", "/search/query", search.searchQuery],
  ["GET", "/secrets_vault", secrets_vault.secretsVaultList],
  ["GET", "/secrets_vault/access", secrets_vault.secretsVaultAccessLog],
  ["PUT", "/secrets_vault/{name}", secrets_vault.secretsVaultPut],
  ["GET", "/secrets_vault/{name}", secrets_vault.secretsVaultGet],
  ["POST", "/secrets_vault/{name}/reveal", secrets_vault.secretsVaultReveal],
  ["POST", "/secrets_vault/{name}/destroy", secrets_vault.secretsVaultDestroy],
  ["POST", "/secrets_vault/{name}/disable", secrets_vault.secretsVaultDisable],
  ["POST", "/secrets_vault/{name}/enable", secrets_vault.secretsVaultEnable],
  ["GET", "/settings", settings.settingsList],
  ["GET", "/settings/{key}", settings.settingsGet],
  ["PUT", "/settings/{key}", settings.settingsPut],
  ["POST", "/storage", storage.storagePut],
  ["GET", "/storage", storage.storageList],
  ["GET", "/storage/{object_key}", storage.storageGet],
  ["DELETE", "/storage/{object_key}", storage.storageDelete],
  ["POST", "/stripe/charges", stripe.stripeCharge],
  ["POST", "/stripe/webhook", stripe.stripeWebhook],
  ["POST", "/teams", teams.teamsCreate],
  ["GET", "/teams/{team_id}", teams.teamsGet],
  ["POST", "/teams/{team_id}/members", teams.teamsAddMember],
  ["DELETE", "/teams/{team_id}/members/{handle}", teams.teamsRemoveMember],
  ["POST", "/tenancy/notes", tenancy.tenancyCreate],
  ["GET", "/tenancy/notes", tenancy.tenancyList],
  ["GET", "/tenancy/notes/{note_id}", tenancy.tenancyGet],
  ["POST", "/users", users.usersCreate],
  ["GET", "/users/{handle}", users.usersGet],
  ["POST", "/users/{handle}/deactivate", users.usersDeactivate],
  ["POST", "/vectors", vectorstore.vectorstoreIndex],
  ["POST", "/vectors/query", vectorstore.vectorstoreQuery],
  ["POST", "/webhooks/send", webhooks.webhookSend],
  ["POST", "/webhooks/verify", webhooks.webhookVerify],
];

export function makeServer() { return createServer(routes); }
