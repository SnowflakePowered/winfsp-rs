use winfsp_sys::FSP_FSCTL_VOLUME_PARAMS;

#[repr(transparent)]
pub struct VolumeParams(FSP_FSCTL_VOLUME_PARAMS);

impl VolumeParams {
    pub fn new() -> Self {
        let mut params = FSP_FSCTL_VOLUME_PARAMS::default();

        // required
        VolumeParams(params)
    }
}
