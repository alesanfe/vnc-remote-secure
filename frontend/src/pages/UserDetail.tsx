import { Link, useParams } from 'react-router-dom';
import { useI18n } from '../i18n';
import { OperatorDetailPanel } from './Users';

/** Operator detail (/admin/users/:username) — shareable view of one
    identity: role, permissions, passkeys and credential state. The
    underlying panel is the same one the users table expands inline;
    this route just gives it its own URL. */
export default function UserDetail() {
  const { t } = useI18n();
  const { username = '' } = useParams();

  return (
    <>
      <h1 className="page-title">
        {t('users.detail.title')}{' '}
        <code className="mono">{username}</code>
      </h1>
      <OperatorDetailPanel username={username} />
      <p className="muted">
        <Link to="/identities">{t('users.detail.back')}</Link>
      </p>
    </>
  );
}
