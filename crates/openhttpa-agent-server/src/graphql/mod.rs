pub mod attestation;
pub mod domains;
pub mod keys;
pub mod messages;

use async_graphql::{MergedObject, MergedSubscription, Schema};

#[derive(MergedObject, Default)]
pub struct QueryRoot(
    keys::KeysQuery,
    messages::MessagesQuery,
    attestation::AttestationQuery,
    domains::finance::FinanceQuery,
);

#[derive(MergedObject, Default)]
pub struct MutationRoot(
    keys::KeysMutation,
    messages::MessagesMutation,
    domains::finance::FinanceMutation,
    domains::medical::MedicalMutation,
    domains::commerce::CommerceMutation,
    domains::voting::VotingMutation,
);

#[derive(MergedSubscription, Default)]
pub struct SubscriptionRoot(messages::MessagesSubscription);

pub type AppSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

pub fn build_schema() -> AppSchema {
    Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        SubscriptionRoot::default(),
    )
    .finish()
}
