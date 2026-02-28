/// <reference types="astro/client" />

declare namespace App {
    interface Locals {
        nonce: string;
        user?: {
            email: string;
            isAdmin: boolean;
        };
    }
}
