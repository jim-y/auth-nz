'use client';

import styles from "./page.module.css";
import { useEffect, useState } from 'react';

export default function Home() {
  const [resource, setResource] = useState();

  const [session, setSession] = useState<{ email: string; access_token: string; } | null>(null)
  useEffect(() => {
    const getSession = async () => {
      const resp = await fetch('/api/auth/session', {
        credentials: "same-origin"
      });
      const session = await resp.json();
      setSession(session);
    }
    void getSession();
  }, []);

  const fetchResource = async () => {
    const resp = await fetch('http://localhost:9000/api/resource/1', {
      headers: {
        authorization: `Bearer ${session?.access_token}`
      }
    });
    const resource = await resp.json();
    setResource(resource);
  }

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        {session && (
            <div>
              <span>👋 Hello, {session.email}!</span>
              <div>
                <button onClick={fetchResource}>Fetch Resource</button>
              </div>
            </div>
        )}
        {resource && (
            <pre>{JSON.stringify(resource, null, 4)}</pre>
        )}
      </main>
    </div>
  );
}
