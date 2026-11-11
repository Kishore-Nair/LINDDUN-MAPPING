"""Build a tree-format fixture from real Bahmni paths (round-trips the parser)."""
PATHS = """
bahmni/apps/registration/src/hooks/useCreatePatient.ts
bahmni/apps/registration/src/hooks/usePatientSearch.ts
bahmni/apps/registration/src/utils/fhirPatientMapper.ts
bahmni/apps/registration/src/components/forms/addressInfo/AddressInfo.tsx
bahmni/apps/registration/src/components/forms/contactInfo/ContactInfo.tsx
bahmni/apps/registration/src/components/forms/patientRelationships/PatientRelationships.tsx
bahmni/apps/registration/src/components/patientPhotoUpload/PatientPhotoUpload.tsx
bahmni/apps/registration/src/pages/PatientRegister/PatientRegister.tsx
bahmni/apps/registration/src/__tests__/App.test.tsx
bahmni/apps/clinical/src/services/encounterBundleService.ts
bahmni/apps/clinical/src/services/medicationService.ts
bahmni/apps/clinical/src/stores/allergyStore.ts
bahmni/apps/clinical/src/stores/conditionsAndDiagnosesStore.ts
bahmni/apps/clinical/src/components/patientSearch/PatientSearch.tsx
bahmni/apps/clinical/src/utils/fhir/allergyResourceCreator.ts
bahmni/apps/admin/src/hooks/useAuditLogs.ts
bahmni/apps/admin/src/pages/AuditLog.tsx
bahmni/apps/admin/src/pages/CsvExport.tsx
bahmni/apps/admin/src/pages/CsvUpload.tsx
bahmni/apps/patient-documents/src/services/visitDocumentSaveService.ts
bahmni/apps/patient-documents/src/hooks/useVisitDocuments.ts
bahmni/packages/bahmni-services/src/patientService/patientService.ts
bahmni/packages/bahmni-services/src/authService/authService.ts
bahmni/packages/bahmni-services/src/auditLogService/auditLogService.ts
bahmni/packages/bahmni-services/src/privilegeService/privilegeService.ts
bahmni/packages/bahmni-services/src/documentUploadService/documentUploadService.ts
bahmni/packages/bahmni-services/src/cameraService/useCamera.ts
bahmni/packages/bahmni-services/src/api/client.ts
bahmni/packages/bahmni-widgets/src/patientDetails/PatientDetails.tsx
bahmni/packages/bahmni-widgets/src/search/searchPatient/SearchPatient.tsx
bahmni/packages/bahmni-widgets/src/commandPalette/CommandPalette.tsx
core/admin/src/main/java/org/bahmni/module/admin/csv/persister/PatientPersister.java
core/admin/src/main/java/org/bahmni/module/admin/csv/service/CSVPatientService.java
core/admin/src/main/java/org/bahmni/module/admin/csv/patientmatchingalgorithm/BahmniPatientMatchingAlgorithm.java
core/admin/src/test/java/org/bahmni/module/admin/csv/service/CSVPatientServiceTest.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/client/BahmniOdooClient.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/events/eventListener/PatientSmsEventListener.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/service/impl/PatientDocumentServiceImpl.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/service/impl/SqlSearchServiceImpl.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/dao/impl/PersonAttributeDaoImpl.java
core/bahmnicore-api/src/main/java/org/bahmni/module/bahmnicore/security/PrivilegeConstants.java
core/bahmnicore-api/target/classes/org/bahmni/module/bahmnicore/client/BahmniOdooClient.class
core/bahmnicore-omod/src/main/java/org/bahmni/module/bahmnicore/web/v1_0/controller/EmailCommunicationController.java
core/bahmnicore-omod/src/main/java/org/bahmni/module/bahmnicore/web/v1_0/controller/BahmniPatientImageController.java
core/openmrs-elis-atomfeed-client-omod/src/main/java/org/bahmni/module/elisatomfeedclient/api/worker/OpenElisPatientFeedWorker.java
core/jss-old-data/src/main/java/org/bahmni/datamigration/csv/PatientPersister.java
core/obs-relation/src/main/java/org/bahmni/module/obsrelationship/dao/impl/ObsRelationshipDaoImpl.java
""".split()

tree, seen = {}, []
for p in PATHS:
    node = tree
    for part in p.split("/"):
        node = node.setdefault(part, {})

def emit(node, prefix=""):
    items = list(node.items())
    for i, (name, kids) in enumerate(items):
        last = i == len(items) - 1
        print(f"{prefix}{'└── ' if last else '├── '}{name}")
        if kids:
            emit(kids, prefix + ("    " if last else "│   "))

print("bahmni-system")
emit(tree)
print(f"\n0 directories, {len(PATHS)} files")
