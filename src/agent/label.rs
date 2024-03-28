// Global namespace for most generic/common labels
pub const LABEL_INSTANCE_ID: &str = "instance-id";
pub const LABEL_INSTANCE_TAG: &str = "instance-tag";
pub const LABEL_IMAGE_ID: &str = "image-id";
pub const LABEL_IMAGE_TAG: &str = "image-tag";

// Cloud namespace (cloud)
pub const LABEL_CLOUD_PROVIDER: &str = "cloud:provider";
pub const LABEL_CLOUD_REGION: &str = "cloud:region";
pub const LABEL_CLOUD_ZONE: &str = "cloud:zone";
pub const LABEL_CLOUD_ACCOUNT_ID: &str = "cloud:account-id";
pub const LABEL_CLOUD_PROJECT_ID: &str = "cloud:project-id";

// Kube namespace (kube)
// General structure:
//   kube:<resource>:name (e.g. kube:pod:name)
//   kube:<resource>:labels:<label> (e.g. kube:pod:labels:app.kubernetes.io/managed-by)
pub const LABEL_KUBE_POD_NAME: &str = "kube:pod:name";
pub const LABEL_KUBE_NAMESPACE_NAME: &str = "kube:namespace:name";
