import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useAuth } from '../../context/AuthContext';
import {
  getAdminUsers,
  preAuthorizeUser,
  updateUserStatus,
  updateUserRole,
  revokeUserAccess,
} from '../../services/apiClient';
import StatusBadge from '../StatusBadge';
import ConfirmDialog from '../common/ConfirmDialog';

export default function UserManagementPanel() {
  const { user: currentUser } = useAuth();

  const [users, setUsers] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState({});
  const [error, setError] = useState(null);
  const [successNotice, setSuccessNotice] = useState(null);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Pre-authorization form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState('USER');
  const [submittingPreAuth, setSubmittingPreAuth] = useState(false);
  const [preAuthError, setPreAuthError] = useState(null);

  // Confirm dialog state for role change or revocation
  const [confirmModal, setConfirmModal] = useState(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAdminUsers({
        limit: 100,
        offset: 0,
        role: roleFilter || null,
        status: statusFilter || null,
      });
      setUsers(data.users || []);
      setTotalCount(data.total_count ?? (data.users || []).length);
    } catch (err) {
      setError(err.message || 'Failed to load authorized users.');
    } finally {
      setLoading(false);
    }
  }, [roleFilter, statusFilter]);

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  // Derived metrics
  const activeCount = useMemo(() => users.filter((u) => u.status === 'ACTIVE').length, [users]);
  const disabledCount = useMemo(() => users.filter((u) => u.status === 'DISABLED').length, [users]);
  const adminCount = useMemo(() => users.filter((u) => u.role === 'ADMIN' && u.status === 'ACTIVE').length, [users]);

  // Client-side search filtering
  const filteredUsers = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return users;
    return users.filter(
      (u) =>
        u.email?.toLowerCase().includes(q) ||
        u.full_name?.toLowerCase().includes(q) ||
        u.user_id?.toLowerCase().includes(q)
    );
  }, [users, searchQuery]);

  // Handle pre-authorization submit
  const handlePreAuthorize = async (e) => {
    e.preventDefault();
    if (!newEmail.trim()) {
      setPreAuthError('Email address is required.');
      return;
    }
    setSubmittingPreAuth(true);
    setPreAuthError(null);
    try {
      const created = await preAuthorizeUser({
        email: newEmail.trim(),
        role: newRole,
        full_name: newName.trim() || null,
      });
      setSuccessNotice(`Successfully pre-authorized ${created.email} (${created.role}).`);
      setNewEmail('');
      setNewName('');
      setNewRole('USER');
      setShowAddForm(false);
      await fetchUsers();
      setTimeout(() => setSuccessNotice(null), 5000);
    } catch (err) {
      setPreAuthError(err.message || 'Failed to pre-authorize account.');
    } finally {
      setSubmittingPreAuth(false);
    }
  };

  // Toggle user status (Activate / Disable)
  const handleToggleStatus = async (targetUser) => {
    const newStatus = targetUser.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
    setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: true }));
    setError(null);
    try {
      const updated = await updateUserStatus(targetUser.user_id, newStatus);
      setSuccessNotice(`User ${updated.email} is now ${updated.status}.`);
      await fetchUsers();
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err) {
      setError(err.message || 'Failed to update user status.');
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: false }));
    }
  };

  // Change user role (ADMIN <-> USER)
  const handleToggleRole = async (targetUser) => {
    const newRole = targetUser.role === 'ADMIN' ? 'USER' : 'ADMIN';
    setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: true }));
    setError(null);
    try {
      const updated = await updateUserRole(targetUser.user_id, newRole);
      setSuccessNotice(`Updated role for ${updated.email} to ${updated.role}.`);
      await fetchUsers();
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err) {
      setError(err.message || 'Failed to update user role.');
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: false }));
    }
  };

  // Revoke user access
  const handleRevokeUser = async (targetUser) => {
    setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: true }));
    setError(null);
    try {
      await revokeUserAccess(targetUser.user_id);
      setSuccessNotice(`Revoked access and removed user ${targetUser.email}.`);
      setConfirmModal(null);
      await fetchUsers();
      setTimeout(() => setSuccessNotice(null), 4000);
    } catch (err) {
      setError(err.message || 'Failed to revoke user access.');
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.user_id]: false }));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Alert Notices */}
      {error && (
        <div className="alert-box alert-error" role="alert" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>{error}</div>
          <button type="button" onClick={() => setError(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {successNotice && (
        <div className="alert-box alert-success" role="status" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>✓ {successNotice}</div>
          <button type="button" onClick={() => setSuccessNotice(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', fontWeight: 'bold' }}>✕</button>
        </div>
      )}

      {/* Metrics Banner */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '14px',
        }}
      >
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Authorized</span>
          <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>{totalCount}</div>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Active Accounts</span>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#10B981', marginTop: '4px' }}>{activeCount}</div>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Disabled Accounts</span>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#EF4444', marginTop: '4px' }}>{disabledCount}</div>
        </div>
        <div className="card" style={{ padding: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Active Administrators</span>
          <div style={{ fontSize: '22px', fontWeight: 700, color: '#6366F1', marginTop: '4px' }}>{adminCount}</div>
        </div>
      </div>

      {/* Action Header & Search */}
      <div className="card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Authorized User Directory
            </h2>
            <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', margin: '2px 0 0' }}>
              Pre-authorize Google identities, manage roles, and control active operational access.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => {
                setShowAddForm(!showAddForm);
                setPreAuthError(null);
              }}
            >
              {showAddForm ? '✕ Cancel' : '+ Pre-Authorize User'}
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={fetchUsers}
              disabled={loading}
              title="Reload user directory"
            >
              ↻ Refresh
            </button>
          </div>
        </div>

        {/* Pre-Authorization Form Card */}
        {showAddForm && (
          <div
            style={{
              padding: '16px',
              borderRadius: '8px',
              backgroundColor: 'var(--bg-void)',
              border: '1px solid #6366F1',
              marginBottom: '16px',
            }}
          >
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '8px' }}>
              Pre-Authorize New Google Account
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '0 0 12px' }}>
              Account will be initialized in <code>ACTIVE</code> status. The Google identity (<code>google_sub</code>) will be bound securely on the user's first successful sign-in.
            </p>

            {preAuthError && (
              <div className="alert-box alert-error" style={{ marginBottom: '12px', padding: '8px 12px', fontSize: '12px' }}>
                {preAuthError}
              </div>
            )}

            <form onSubmit={handlePreAuthorize} style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'flex-end' }}>
              <div style={{ flex: '1 1 240px' }}>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
                  Google Account Email *
                </label>
                <input
                  type="email"
                  className="form-input"
                  placeholder="e.g. security-analyst@organization.com"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  style={{ width: '100%', fontSize: '12px' }}
                  required
                />
              </div>

              <div style={{ flex: '1 1 200px' }}>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
                  Full Name (Optional)
                </label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Jane Developer"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  style={{ width: '100%', fontSize: '12px' }}
                />
              </div>

              <div style={{ flex: '0 1 140px' }}>
                <label style={{ fontSize: '11.5px', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
                  Assigned Role
                </label>
                <select
                  className="form-input"
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{ width: '100%', fontSize: '12px' }}
                >
                  <option value="USER">USER</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
              </div>

              <div>
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={submittingPreAuth}
                  style={{ height: '36px' }}
                >
                  {submittingPreAuth ? 'Authorizing...' : 'Authorize Account'}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Filter & Search Bar */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center' }}>
          <div style={{ flex: '1 1 220px' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Search by email, name, or user ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ width: '100%', fontSize: '12px' }}
            />
          </div>
          <div style={{ width: '130px' }}>
            <select
              className="form-input"
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              style={{ width: '100%', fontSize: '12px' }}
            >
              <option value="">All Roles</option>
              <option value="ADMIN">ADMIN</option>
              <option value="USER">USER</option>
            </select>
          </div>
          <div style={{ width: '130px' }}>
            <select
              className="form-input"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ width: '100%', fontSize: '12px' }}
            >
              <option value="">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="DISABLED">DISABLED</option>
            </select>
          </div>
        </div>

        {/* Users Table */}
        <div style={{ overflowX: 'auto', marginTop: '16px' }}>
          {loading ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              Loading authorized users...
            </div>
          ) : filteredUsers.length === 0 ? (
            <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No authorized users found matching the selected filters.
            </div>
          ) : (
            <table className="cs-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  <th style={{ padding: '10px 12px' }}>User</th>
                  <th style={{ padding: '10px 12px' }}>Google Identity</th>
                  <th style={{ padding: '10px 12px' }}>Role</th>
                  <th style={{ padding: '10px 12px' }}>Status</th>
                  <th style={{ padding: '10px 12px' }}>Audit Timeline</th>
                  <th style={{ padding: '10px 12px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((u) => {
                  const isSelf = currentUser && u.user_id === currentUser.user_id;
                  const isLastAdmin = u.role === 'ADMIN' && u.status === 'ACTIVE' && adminCount <= 1;
                  const isBusy = actionLoading[u.user_id];

                  return (
                    <tr
                      key={u.user_id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        fontSize: '12.5px',
                        backgroundColor: isSelf ? 'rgba(99, 102, 241, 0.03)' : 'transparent',
                      }}
                    >
                      {/* User Avatar + Email + Name */}
                      <td style={{ padding: '12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <div
                            style={{
                              width: '32px',
                              height: '32px',
                              borderRadius: '50%',
                              backgroundColor: u.role === 'ADMIN' ? '#6366F1' : '#64748B',
                              color: '#FFFFFF',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '12px',
                              fontWeight: 700,
                              flexShrink: 0,
                            }}
                          >
                            {u.profile_picture ? (
                              <img
                                src={u.profile_picture}
                                alt={u.full_name || u.email}
                                style={{ width: '100%', height: '100%', borderRadius: '50%', objectFit: 'cover' }}
                                referrerPolicy="no-referrer"
                              />
                            ) : (
                              (u.full_name ? u.full_name[0] : u.email[0]).toUpperCase()
                            )}
                          </div>
                          <div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {u.full_name || '—'} {isSelf && <span style={{ fontSize: '10px', color: '#6366F1', fontWeight: 700 }}>(You)</span>}
                            </div>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{u.email}</div>
                          </div>
                        </div>
                      </td>

                      {/* Google Identity Binding */}
                      <td style={{ padding: '12px' }}>
                        {u.google_sub ? (
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(16, 185, 129, 0.1)',
                              color: '#059669',
                              border: '1px solid rgba(16, 185, 129, 0.2)',
                            }}
                            title={`Google Sub: ${u.google_sub}`}
                          >
                            ✓ Bound
                          </span>
                        ) : (
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 600,
                              padding: '2px 8px',
                              borderRadius: '4px',
                              backgroundColor: 'rgba(245, 158, 11, 0.1)',
                              color: '#D97706',
                              border: '1px solid rgba(245, 158, 11, 0.2)',
                            }}
                            title="Unbound until user completes first Google authentication"
                          >
                            ⏳ Pending Login
                          </span>
                        )}
                      </td>

                      {/* Role */}
                      <td style={{ padding: '12px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            fontWeight: 700,
                            padding: '3px 8px',
                            borderRadius: '4px',
                            backgroundColor: u.role === 'ADMIN' ? 'rgba(99, 102, 241, 0.12)' : 'var(--bg-void)',
                            color: u.role === 'ADMIN' ? '#4F46E5' : 'var(--text-muted)',
                            border: '1px solid var(--border-subtle)',
                          }}
                        >
                          {u.role}
                        </span>
                      </td>

                      {/* Status */}
                      <td style={{ padding: '12px' }}>
                        <StatusBadge status={u.status === 'ACTIVE' ? 'PASS' : 'FAIL'} />
                      </td>

                      {/* Audit */}
                      <td style={{ padding: '12px', fontSize: '11px', color: 'var(--text-muted)' }}>
                        <div>Created: {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}</div>
                        <div>Last Login: {u.last_login ? new Date(u.last_login).toLocaleDateString() : 'Never'}</div>
                        {u.created_by && <div style={{ fontSize: '10px' }}>By: {u.created_by}</div>}
                      </td>

                      {/* Actions */}
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                          {/* Role Toggle Button */}
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            disabled={isBusy || (isSelf && u.role === 'ADMIN') || isLastAdmin}
                            onClick={() => handleToggleRole(u)}
                            title={
                              isSelf && u.role === 'ADMIN'
                                ? 'Cannot demote your own account'
                                : isLastAdmin
                                ? 'Cannot demote the last active administrator'
                                : `Change role to ${u.role === 'ADMIN' ? 'USER' : 'ADMIN'}`
                            }
                            style={{ fontSize: '11px', padding: '3px 8px' }}
                          >
                            {u.role === 'ADMIN' ? 'Demote to USER' : 'Promote to ADMIN'}
                          </button>

                          {/* Status Toggle Button */}
                          <button
                            type="button"
                            className={`btn btn-sm ${u.status === 'ACTIVE' ? 'btn-secondary' : 'btn-primary'}`}
                            disabled={isBusy || (isSelf && u.status === 'ACTIVE') || (isLastAdmin && u.status === 'ACTIVE')}
                            onClick={() => handleToggleStatus(u)}
                            title={
                              isSelf && u.status === 'ACTIVE'
                                ? 'Cannot disable your own account'
                                : isLastAdmin && u.status === 'ACTIVE'
                                ? 'Cannot disable the last active administrator'
                                : u.status === 'ACTIVE' ? 'Disable account' : 'Activate account'
                            }
                            style={{ fontSize: '11px', padding: '3px 8px' }}
                          >
                            {u.status === 'ACTIVE' ? 'Disable' : 'Activate'}
                          </button>

                          {/* Revoke Button */}
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            disabled={isBusy || isSelf || isLastAdmin}
                            onClick={() => setConfirmModal(u)}
                            title={
                              isSelf
                                ? 'Cannot revoke your own account'
                                : isLastAdmin
                                ? 'Cannot revoke the last active administrator'
                                : 'Revoke authorization and remove user record'
                            }
                            style={{ fontSize: '11px', padding: '3px 8px', color: '#EF4444' }}
                          >
                            Revoke
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Revocation Confirmation Dialog */}
      <ConfirmDialog
        isOpen={Boolean(confirmModal)}
        title="Revoke Account Authorization?"
        message={`Are you sure you want to revoke access for ${confirmModal?.email || ''}? All active sessions will be terminated immediately. Historical security scan records and findings will remain preserved.`}
        confirmLabel="Confirm Revocation"
        cancelLabel="Cancel"
        isDestructive={true}
        isProcessing={Boolean(confirmModal && actionLoading[confirmModal.user_id])}
        onConfirm={() => confirmModal && handleRevokeUser(confirmModal)}
        onCancel={() => setConfirmModal(null)}
      />
    </div>
  );
}
