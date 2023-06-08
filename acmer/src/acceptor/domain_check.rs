use std::{collections::HashSet, sync::Arc};

use dashmap::DashSet;

/// This trait provides a way to filter the domains allowed to have TLS certificates emitted.
pub trait DomainCheck: Send + Sync {
    fn allow_domain(&self, domain: &str) -> bool;
}

impl<F> DomainCheck for F
where
    F: Fn(&str) -> bool,
    F: Send + Sync,
{
    fn allow_domain(&self, domain: &str) -> bool {
        self(domain)
    }
}

impl DomainCheck for &str {
    fn allow_domain(&self, domain: &str) -> bool {
        self == &domain
    }
}

impl DomainCheck for String {
    fn allow_domain(&self, domain: &str) -> bool {
        self == domain
    }
}

impl DomainCheck for bool {
    fn allow_domain(&self, _domain: &str) -> bool {
        *self
    }
}

impl<const N: usize> DomainCheck for &[&str; N] {
    fn allow_domain(&self, domain: &str) -> bool {
        self.contains(&domain)
    }
}

impl DomainCheck for HashSet<String> {
    fn allow_domain(&self, domain: &str) -> bool {
        self.contains(domain)
    }
}

impl DomainCheck for DashSet<String> {
    fn allow_domain(&self, domain: &str) -> bool {
        self.contains(domain)
    }
}

impl DomainCheck for Arc<DashSet<String>> {
    fn allow_domain(&self, domain: &str) -> bool {
        self.contains(domain)
    }
}
