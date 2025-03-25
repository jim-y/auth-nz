'use client';

import { useSearchParams } from 'next/navigation';
import { MouseEvent } from 'react';

export default function signInPage() {
    const searchParams = useSearchParams();
    const redirectTo = searchParams.get('redirectTo');

    const setDecisionTo = (form: HTMLFormElement, decision: 'grant' | 'deny') => {
        const decisionElement = form.elements.namedItem('decision');
        if (decisionElement && decisionElement instanceof HTMLInputElement) {
            decisionElement.value = decision === 'grant' ? '1' : '0';
        }
    };

    const grant = (event: MouseEvent<HTMLButtonElement>) => {
        event.preventDefault();
        const form = document.forms.namedItem('consentForm');
        if (form) {
            setDecisionTo(form, 'grant');
            form.submit();
        }
    };

    const deny = (event: MouseEvent<HTMLButtonElement>) => {
        event.preventDefault();
        const form = document.forms.namedItem('consentForm');
        if (form) {
            setDecisionTo(form, 'deny');
            form.submit();
        }
    };

    return (
        <div style={{ display: 'flex' }}>
            <form
                action={String(redirectTo)}
                name="consentForm"
                method="POST"
                style={{ width: '300px', margin: '10% auto', display: 'flex', flexDirection: 'column', gap: '1rem' }}
            >
                <h2 style={{ textAlign: 'center' }}>Consent</h2>
                <div style={{ textAlign: 'center' }}>
                    XY wants to access your data. Do you provide consent?
                </div>
                <input type="hidden" name="decision" />
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 0' }}>
                    <button onClick={deny}>Deny</button>
                    <button onClick={grant}>Grant</button>
                </div>
            </form>
        </div>
    );
}
