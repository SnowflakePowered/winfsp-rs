use windows::{
    core::HRESULT, Wdk::Storage::FileSystem::FILE_DISPOSITION_INFORMATION_EX_FLAGS,
    Win32::Foundation::NTSTATUS,
};

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct FILE_FS_SIZE_INFORMATION {
    pub TotalAllocationUnits: i64,
    pub AvailableAllocationUnits: i64,
    pub SectorsPerAllocationUnit: u32,
    pub BytesPerSector: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct FILE_DISPOSITION_INFORMATION_EX {
    pub Flags: FILE_DISPOSITION_INFORMATION_EX_FLAGS,
}

pub trait ToNtStatus {
    fn to_ntstatus(&self) -> NTSTATUS;
}

impl ToNtStatus for HRESULT {
    fn to_ntstatus(&self) -> NTSTATUS {
        NTSTATUS(&self.0 & !(1 << 28))
    }
}
