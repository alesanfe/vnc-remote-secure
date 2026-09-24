import { useQuery } from '@tanstack/react-query';
import { api, type OperatorUser } from '../api';

export default function Users() {
  const ops = useQuery({
    queryKey: ['operators'],
    queryFn: () => api.get<{ operators: OperatorUser[] }>('operators'),
  });

  return (
    <>
      <h1 className="page-title">Usuarios</h1>
      <p className="muted">
        Cuentas de operador del portal. La gestión de usuarios de sistema y
        passkeys sigue en la <a href="/users">UI clásica</a> por ahora.
      </p>

      {ops.isError && (
        <div className="error-box">
          No se pudieron cargar los operadores (¿falta el permiso admin_users?).
        </div>
      )}
      <table className="data">
        <thead>
          <tr>
            <th>Usuario</th>
            <th>Rol</th>
            <th>Estado</th>
            <th>Permisos</th>
            <th>Creado</th>
          </tr>
        </thead>
        <tbody>
          {(ops.data?.operators ?? []).map((u) => (
            <tr key={u.username}>
              <td>{u.username}</td>
              <td>{u.role}</td>
              <td>
                <span className={`badge ${u.disabled ? 'fail' : 'ok'}`}>
                  {u.disabled ? 'Deshabilitado' : 'Activo'}
                </span>
              </td>
              <td title={u.permissions.join(', ')}>
                {u.permissions.length} perm
              </td>
              <td>
                {u.created_at
                  ? new Date(u.created_at * 1000).toLocaleString()
                  : '—'}
              </td>
            </tr>
          ))}
          {ops.data && ops.data.operators.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                Sin cuentas almacenadas — el operador env (bootstrap admin)
                está en uso.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
