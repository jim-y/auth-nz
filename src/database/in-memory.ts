import EventEmitter from 'node:events';
import { CustomEvents } from './custom-events.ts';

type Table = 'grant' | 'session';

export class InMemoryAdapter extends EventEmitter {
    #store =  {
        grant: [],
        session: new Map()
    }

    async insert(table: Table, payload: any, uid?: string) {
        switch (table) {
            case 'grant':
                this.#store.grant.push(payload);
                break;
            case 'session':
                this.#store.session.set(uid, payload);
                break;
        }
        this.emit(CustomEvents.insert, {
            table,
            payload,
            uid
        });
    }

    async fetch(table: Table, predicate: string, value?: any) {
        let response;
        switch (table) {
            case 'grant':
                response = this.#store.grant.find((item) => item[predicate] === value);
                break;
            case 'session':
                response = this.#store.session.get(predicate);
                break;
        }
        this.emit(CustomEvents.fetch, {
            table,
            predicate,
            response
        });
        return response;
    }

    async update(table: Table, uid: string, updates) {
        switch (table) {
            case 'session':
                const session = this.#store.session.get(uid);
                this.#store.session.set(uid, Object.assign(session, updates));
                break;
        }
        this.emit(CustomEvents.update, {
            uid,
            updates
        });
    }
}

export const database = new InMemoryAdapter();
