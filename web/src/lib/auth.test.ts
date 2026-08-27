import { describe, it, expect, beforeEach } from 'vitest';
import {
  __resetAuth, login, me, resetRequest, resetVerify, registerRequest, registerVerify, HttpError,
} from './auth';

beforeEach(() => {
  __resetAuth();
  delete process.env.BREVO_API_KEY; // demo-otp path
});

describe('auth', () => {
  it('seeded admin can log in and be identified by token', async () => {
    const r = await login('admin@mailtrace.io', 'demo1234');
    expect(r.user.email).toBe('admin@mailtrace.io');
    const u = await me(r.token);
    expect(u.role).toBe('Administrator');
  });

  it('wrong password is rejected', async () => {
    await expect(login('admin@mailtrace.io', 'nope')).rejects.toBeInstanceOf(HttpError);
  });

  it('two-step signup: account does not exist until the OTP is verified', async () => {
    const req = await registerRequest('alice@example.com', 'hunter2x', 'Alice');
    expect(req.demo_otp).toBeTruthy();
    // not yet an account
    await expect(login('alice@example.com', 'hunter2x')).rejects.toBeInstanceOf(HttpError);
    // wrong code
    await expect(registerVerify('alice@example.com', '000000')).rejects.toBeInstanceOf(HttpError);
    // correct code creates + signs in
    const done = await registerVerify('alice@example.com', req.demo_otp as string);
    expect(done.user.email).toBe('alice@example.com');
    expect((await login('alice@example.com', 'hunter2x')).user.email).toBe('alice@example.com');
  });

  it('duplicate signup is 409', async () => {
    await expect(registerRequest('admin@mailtrace.io', 'whatever', 'x')).rejects.toMatchObject({ status: 409 });
  });

  it('password reset via OTP', async () => {
    const req = await resetRequest('admin@mailtrace.io');
    expect(req.demo_otp).toBeTruthy();
    await expect(resetVerify('admin@mailtrace.io', '000000', 'newpass1')).rejects.toBeInstanceOf(HttpError);
    const done = await resetVerify('admin@mailtrace.io', req.demo_otp as string, 'newpass1');
    expect(done.user.email).toBe('admin@mailtrace.io');
    expect((await login('admin@mailtrace.io', 'newpass1')).user.email).toBe('admin@mailtrace.io');
  });

  it('reset for unknown email is 404', async () => {
    await expect(resetRequest('nobody@nowhere.test')).rejects.toMatchObject({ status: 404 });
  });
});
