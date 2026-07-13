use url::Url;

use crate::model::Observation;

#[derive(Debug)]
pub struct FetchedResponse {
    pub observation: Observation,
    pub effective_url: Url,
    pub body: Vec<u8>,
}

impl FetchedResponse {
    #[must_use]
    pub fn text_lossy(&self) -> Option<String> {
        self.observation
            .content_kind
            .is_text()
            .then(|| String::from_utf8_lossy(&self.body).into_owned())
    }
}
