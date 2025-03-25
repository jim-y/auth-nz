'use client';

import { useSearchParams } from 'next/navigation';

export default function OidcErrorPage() {
    const searchParams = useSearchParams();
    return (
        <div style={{ width: '300px', display: 'flex', flexDirection: 'column', gap: '20px', margin: '10% auto' }}>
            <h2>AuthNZ Error</h2>
            {Array.from(searchParams.entries()).map(([key, value]) => (
                <div key={key}>
                    <h3 style={{ color: 'green' }}>{key}</h3>
                    <p>{value}</p>
                </div>
            ))}
        </div>
    )
}