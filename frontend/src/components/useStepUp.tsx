import { useState } from 'react';
import { ApiError } from '../api';
import StepUpDialog from './StepUpDialog';

/**
 * Shared step-up gating for mutations: when the API answers
 * STEP_UP_REQUIRED the hook opens the re-auth dialog and retries the
 * originally blocked action once the grant lands.
 *
 * Usage:
 *   const stepUp = useStepUp();
 *   useMutation({ ..., onError: (e, vars) => {
 *     if (stepUp.gate(e, 'descripción', () => act.mutate(vars))) return;
 *     // hard-failure rendering
 *   }});
 *   return (<>{page}{stepUp.dialog}</>);
 */
export function useStepUp() {
  const [pending, setPending] = useState<{
    op: string;
    opId?: string;
    resource?: string;
    retry: () => void;
  } | null>(null);

  /** Call from a mutation's onError — returns true when the error was
      consumed by the step-up gate (don't also surface it as a hard
      failure). ``bind.opId`` binds the grant to the catalog
      operation id; the server consumes it once for that exact
      operation+resource. */
  const gate = (e: unknown, op: string, retry: () => void,
                bind?: { opId?: string; resource?: string }): boolean => {
    if (e instanceof ApiError && e.code === 'STEP_UP_REQUIRED') {
      setPending({ op, retry, opId: bind?.opId,
                   resource: bind?.resource });
      return true;
    }
    return false;
  };

  const dialog = (
    <StepUpDialog
      open={pending !== null}
      operation={pending?.op ?? ''}
      operationId={pending?.opId}
      resource={pending?.resource}
      onCancel={() => setPending(null)}
      onVerified={() => {
        const retry = pending?.retry;
        setPending(null);
        retry?.();
      }}
    />
  );

  return { gate, dialog };
}
