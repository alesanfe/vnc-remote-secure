import { Link } from 'react-router-dom';
import { useI18n } from '../i18n';

const STEPS = ['invite', 'share', 'consent', 'supervise', 'close'] as const;
const CONCEPTS = ['session', 'invite', 'sharelink', 'connection',
                  'opsession', 'grant', 'stepup', 'job', 'label',
                  'audit'] as const;

/** Contextual help — the onboarding tour the console didn't have:
    the invite→consent→monitor→close flow in plain language, a
    glossary for the security vocabulary, and deep links into the
    sections an operator actually visits first. */
export default function Help() {
  const { t } = useI18n();
  return (
    <>
      <h1 className="page-title">{t('help.title')}</h1>
      <p className="muted">{t('help.subtitle')}</p>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>{t('help.flow.title')}</h3>
        <ol className="timeline">
          {STEPS.map((s) => (
            <li key={s}>
              <strong>{t(`help.flow.${s}.title`)}</strong>
              <p className="muted" style={{ margin: '0.2rem 0' }}>
                {t(`help.flow.${s}.desc`)}
              </p>
            </li>
          ))}
        </ol>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>{t('help.glossary')}</h3>
        <dl className="kv">
          {CONCEPTS.map((c) => (
            <div key={c} style={{ display: 'contents' }}>
              <dt>{t(`help.term.${c}`)}</dt>
              <dd className="muted">{t(`help.term.${c}.desc`)}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>{t('help.links')}</h3>
        <div className="row" style={{ flexWrap: 'wrap' }}>
          <Link to="/access">{t('nav.sessions')}</Link>
          <Link to="/remote">{t('nav.remote')}</Link>
          <Link to="/security">{t('nav.security')}</Link>
          <Link to="/operations/jobs">{t('nav.jobs')}</Link>
          <Link to="/config">{t('nav.config')}</Link>
        </div>
      </div>
    </>
  );
}
