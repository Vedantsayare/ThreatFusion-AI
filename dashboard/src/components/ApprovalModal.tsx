import React, { useState } from 'react';
import { CheckCircle, XCircle, X } from 'lucide-react';

interface ApprovalModalProps {
  requestId: string;
  actionSummary: string;
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (requestId: string, decision: 'APPROVE' | 'REJECT', reviewerId: string, reason: string) => Promise<void>;
}

export const ApprovalModal: React.FC<ApprovalModalProps> = ({
  requestId,
  actionSummary,
  isOpen,
  onClose,
  onSubmit,
}) => {
  const [reviewerId, setReviewerId] = useState('secops-analyst-1');
  const [reason, setReason] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleDecision = async (decision: 'APPROVE' | 'REJECT') => {
    if (!reviewerId.trim()) {
      setError('Reviewer ID is required.');
      return;
    }
    setError(null);
    setIsSubmitting(true);
    try {
      await onSubmit(requestId, decision, reviewerId, reason);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Failed to submit decision.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Human-in-the-Loop Approval Decision</h3>
          <button className="btn btn-secondary" onClick={onClose} style={{ padding: '0.2rem' }}>
            <X size={16} />
          </button>
        </div>

        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Review the containment action before approving or rejecting execution.
        </div>

        <div className="sub-panel" style={{ fontSize: '0.82rem' }}>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Action Target:</div>
          <div className="mono" style={{ color: 'var(--accent-cyan)' }}>{actionSummary}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>Request ID: {requestId}</div>
        </div>

        <div>
          <label style={{ fontSize: '0.8rem', fontWeight: 500, display: 'block', marginBottom: '0.35rem' }}>
            Reviewer ID
          </label>
          <input
            type="text"
            className="search-input"
            value={reviewerId}
            onChange={(e) => setReviewerId(e.target.value)}
            placeholder="e.g. secops-analyst-1"
          />
        </div>

        <div>
          <label style={{ fontSize: '0.8rem', fontWeight: 500, display: 'block', marginBottom: '0.35rem' }}>
            Decision Rationale / Notes
          </label>
          <textarea
            className="textarea-field"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Document rationale for audit trail (e.g., Host confirmed malicious via C2 callback)..."
          />
        </div>

        {error && (
          <div style={{ color: 'var(--danger)', fontSize: '0.8rem' }}>{error}</div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <button
            className="btn btn-danger"
            onClick={() => handleDecision('REJECT')}
            disabled={isSubmitting}
            id="btn-modal-reject"
          >
            <XCircle size={14} />
            <span>Reject Action</span>
          </button>
          <button
            className="btn btn-success"
            onClick={() => handleDecision('APPROVE')}
            disabled={isSubmitting}
            id="btn-modal-approve"
          >
            <CheckCircle size={14} />
            <span>Approve Action</span>
          </button>
        </div>
      </div>
    </div>
  );
};
