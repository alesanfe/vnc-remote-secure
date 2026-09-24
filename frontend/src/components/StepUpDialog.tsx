import ConfirmDialog from './ConfirmDialog';

interface Props {
  open: boolean;
  /** What the operator is about to do — shown verbatim. */
  operation: string;
  /** Affected resource (session, operator, config key…). */
  resource?: string;
  /** Accepted step-up methods (mfa, passkey, password). */
  methods?: string[];
  busy?: boolean;
  onConfirm: (code: string) => void;
  onCancel: () => void;
}

/**
 * Step-up authentication dialog — VISUAL ONLY for now. Destructive
 * operations stay disabled until the backend step-up endpoint
 * (re-auth bound to the operation + resource, short-lived grant)
 * exists; this component just provides the verified UX shell.
 */
export default function StepUpDialog({
  open,
  operation,
  resource,
  methods = ['password'],
  busy = false,
  onConfirm,
  onCancel,
}: Props) {
  return (
    <ConfirmDialog
      open={open}
      title="Confirmación reforzada"
      danger
      busy={busy}
      confirmLabel="Verificar y ejecutar"
      onCancel={onCancel}
      onConfirm={() => onConfirm('')}
    >
      <p>
        Esta operación requiere re-autenticación:
        <strong> {operation}</strong>
        {resource ? (
          <>
            {' '}sobre <code>{resource}</code>
          </>
        ) : null}
        .
      </p>
      <p className="muted">
        Métodos admitidos: {methods.join(', ')}. La verificación se
        vinculará a esta operación y expirará en pocos minutos.
      </p>
      <p className="muted">
        (Pendiente de backend: challenge de step-up y grant firmado.)
      </p>
    </ConfirmDialog>
  );
}
