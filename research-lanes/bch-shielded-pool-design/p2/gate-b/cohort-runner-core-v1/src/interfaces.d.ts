export declare const externalActivationCapability: unique symbol;

export interface ExternalActivationCapability {
  readonly [externalActivationCapability]: never;
}

export interface RetainedDescriptorHandle {
  readonly __kPrivateBrand?: never;
}

export interface AdmittedDispatchHandle {
  readonly __kPrivateBrand?: never;
}

export interface JournalEntryHandle {
  readonly __kPrivateBrand?: never;
}

export interface JournalIndexHandle {
  readonly __kPrivateBrand?: never;
}

export interface PrivateObservationHandle {
  readonly __kPrivateBrand?: never;
}

export interface ExternalMechanismContract {
  readonly executionAllowed: false;
  readonly mechanism: 'module-worker' | 'direct-loader';
  readonly activationCapability: null;
}

export interface DispatchPlanInput {
  readonly dispatchPlanRoot: string;
  readonly rowRoot: string;
  readonly executionAllowed: false;
  readonly workerRows: readonly unknown[];
}
