from pydantic import BaseModel

class LicenseEntry(BaseModel):
    countrycode:str
    companyname:str
    license_type:str
    hash_value:str
    device_limit:str
    validity:str

class ActivateLicense(BaseModel):
    hash_value:str
    email:str

class TrialLicense(BaseModel):
    hash_value:str
    companyname:str
    countrycode:str
    license_type:str
    email:str