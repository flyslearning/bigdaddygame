import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { currentAdmin, createSession, sessionCookie, checkOrigin } from '@/lib/auth';
import { db, log } from '@/lib/db';
export const runtime='nodejs';
export const dynamic='force-dynamic';
const ok=(data:unknown,status=200)=>NextResponse.json(data,{status,headers:{'Cache-Control':'no-store'}});
const bad=(message:string,status=400)=>ok({error:message},status);
type Ctx={params:Promise<{route:string[]}>};
const addressValid=(network:string,address:string)=>network==='ERC20'?/^0x[a-fA-F0-9]{40}$/.test(address):/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
export async function GET(_req:NextRequest, ctx:Ctx){
 try {
 const route=(await ctx.params).route.join('/'); const admin=await currentAdmin();
 if(route==='me')return ok({admin}); if(!admin)return bad('Unauthorized',401);
 const d=db();
 if(route==='overview'){
   const players=d.prepare('SELECT COUNT(*) n, COALESCE(SUM(points),0) points FROM players').get();
   const games=d.prepare('SELECT COUNT(*) n FROM games').get();
   const figures=d.prepare(`SELECT entry_type,SUM(amount_cents) total,COUNT(*) count FROM entries GROUP BY entry_type`).all();
   const activity=d.prepare(`SELECT l.id,l.action,l.details,l.created_at,a.email FROM audit_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 12`).all();
   const daily=d.prepare(`SELECT substr(created_at,1,10) day,entry_type,SUM(amount_cents) amount FROM entries GROUP BY day,entry_type ORDER BY day DESC LIMIT 60`).all();
   return ok({players,games,figures,activity,daily});
 }
 if(route==='players')return ok(d.prepare('SELECT * FROM players ORDER BY id DESC LIMIT 500').all());
 if(route==='games')return ok(d.prepare('SELECT * FROM games ORDER BY id DESC').all());
 if(route==='points')return ok(d.prepare('SELECT p.game_id,p.name,l.* FROM points_ledger l JOIN players p ON p.id=l.player_id ORDER BY l.id DESC LIMIT 300').all());
 if(route==='entries')return ok(d.prepare('SELECT * FROM entries ORDER BY id DESC LIMIT 500').all());
 if(route==='wallets')return ok(d.prepare('SELECT * FROM wallet_addresses ORDER BY id DESC').all());
 if(route==='payouts')return ok(d.prepare('SELECT p.*,w.label,w.network,w.address FROM payout_requests p JOIN wallet_addresses w ON w.id=p.wallet_id ORDER BY p.id DESC').all());
 if(route==='audit')return ok(d.prepare('SELECT l.*,a.email FROM audit_logs l LEFT JOIN admins a ON a.id=l.admin_id ORDER BY l.id DESC LIMIT 300').all());
 return bad('Not found',404);
 }catch(e){console.error(e);return bad('Server error',500)}
}
export async function POST(req:NextRequest,ctx:Ctx){
 try {
 if(!checkOrigin(req)) return bad('Invalid origin',403);
 const route=(await ctx.params).route.join('/');const body=await req.json();const d=db();
 if(route==='login'){
  const v=z.object({email:z.string().email(),password:z.string()}).parse(body);
  const admin=d.prepare('SELECT * FROM admins WHERE email=?').get(v.email.toLowerCase()) as {id:number,pass_hash:string}|undefined;
  if(!admin||!bcrypt.compareSync(v.password,admin.pass_hash))return bad('Invalid credentials',401);
  const res=ok({success:true});res.cookies.set(sessionCookie(createSession(admin.id)));log(admin.id,'LOGIN',{});return res;
 }
 const admin=await currentAdmin();if(!admin)return bad('Unauthorized',401);
 if(route==='logout'){const res=ok({success:true});res.cookies.set({...sessionCookie(''),maxAge:0});return res;}
 if(route==='players'){
  const v=z.object({game_id:z.string().regex(/^[A-Za-z0-9_-]{3,32}$/),name:z.string().trim().min(2).max(80)}).parse(body);
  const r=d.prepare('INSERT INTO players(game_id,name) VALUES (?,?)').run(v.game_id,v.name);log(admin.id,'CREATE_PLAYER',{id:r.lastInsertRowid,...v});return ok({success:true},201);
 }
 if(route==='points'){
  const v=z.object({game_id:z.string().min(3),delta:z.number().int().min(-1000000).max(1000000).refine(x=>x!==0),reason:z.string().trim().min(5).max(200)}).parse(body);
  const r=d.transaction(()=>{
   const p=d.prepare('SELECT id,points FROM players WHERE game_id=? AND status=?').get(v.game_id,'ACTIVE') as {id:number,points:number}|undefined;
   if(!p)throw new Error('Active player Game ID not found');if(p.points+v.delta<0)throw new Error('Insufficient points');
   const after=p.points+v.delta;d.prepare('UPDATE players SET points=? WHERE id=?').run(after,p.id);
   const l=d.prepare('INSERT INTO points_ledger(player_id,delta,balance_after,reason,admin_id) VALUES (?,?,?,?,?)').run(p.id,v.delta,after,v.reason,admin.id);
   log(admin.id,'POINT_ADJUST',{ledger_id:l.lastInsertRowid,game_id:v.game_id,delta:v.delta,after});return {after};
  })();return ok({success:true,...r});
 }
 if(route==='games'){
  const v=z.object({title:z.string().trim().min(2).max(80),slug:z.string().regex(/^[a-z0-9-]{3,40}$/),category:z.string().trim().min(2).max(50)}).parse(body);
  const r=d.prepare('INSERT INTO games(title,slug,category) VALUES (?,?,?)').run(v.title,v.slug,v.category);log(admin.id,'CREATE_GAME',{id:r.lastInsertRowid,...v});return ok({success:true},201);
 }
 if(route==='games/status'){
  const v=z.object({id:z.number().int().positive(),status:z.enum(['ACTIVE','DISABLED'])}).parse(body);
  d.prepare('UPDATE games SET status=? WHERE id=?').run(v.status,v.id);log(admin.id,'GAME_STATUS',v);return ok({success:true});
 }
 if(route==='entries'){
  const v=z.object({entry_type:z.enum(['REVENUE','EXPENSE','DEPOSIT','REFUND']),amount:z.number().positive().max(1e9),memo:z.string().trim().min(3).max(200),reference:z.string().max(100).optional()}).parse(body);
  const cents=Math.round(v.amount*100);const r=d.prepare('INSERT INTO entries(entry_type,amount_cents,memo,reference,admin_id) VALUES (?,?,?,?,?)').run(v.entry_type,cents,v.memo,v.reference||null,admin.id);
  log(admin.id,'ACCOUNTING_ENTRY',{id:r.lastInsertRowid,entry_type:v.entry_type,amount_cents:cents});return ok({success:true},201);
 }
 if(route==='wallets'){
  const v=z.object({label:z.string().trim().min(2).max(60),network:z.enum(['ERC20','TRC20']),address:z.string().trim()}).parse(body);
  if(!addressValid(v.network,v.address))return bad('Invalid address format for selected network');
  const r=d.prepare('INSERT INTO wallet_addresses(label,network,address,admin_id) VALUES (?,?,?,?)').run(v.label,v.network,v.address,admin.id);
  log(admin.id,'WALLET_ADDED',{wallet_id:r.lastInsertRowid,network:v.network,address:v.address});return ok({success:true},201);
 }
 if(route==='wallets/deactivate'){
  const v=z.object({id:z.number().int().positive()}).parse(body);d.prepare('UPDATE wallet_addresses SET active=0 WHERE id=?').run(v.id);log(admin.id,'WALLET_DISABLED',v);return ok({success:true});
 }
 if(route==='payouts'){
  const v=z.object({wallet_id:z.number().int().positive(),amount_usdt:z.string().regex(/^(?:[1-9]\d{0,11})(?:\.\d{1,6})?$/),note:z.string().max(200).optional()}).parse(body);
  const wallet=d.prepare('SELECT id FROM wallet_addresses WHERE id=? AND active=1').get(v.wallet_id);if(!wallet)return bad('Choose an active wallet');
  const r=d.prepare('INSERT INTO payout_requests(wallet_id,amount_usdt,note,admin_id) VALUES (?,?,?,?)').run(v.wallet_id,v.amount_usdt,v.note||null,admin.id);
  log(admin.id,'PAYOUT_DRAFT_CREATED',{id:r.lastInsertRowid,amount_usdt:v.amount_usdt,wallet_id:v.wallet_id});return ok({success:true,notice:'Draft only. No funds transferred.'},201);
 }
 if(route==='payouts/cancel'){
  const v=z.object({id:z.number().int().positive()}).parse(body);d.prepare('UPDATE payout_requests SET status=? WHERE id=? AND status=?').run('CANCELLED',v.id,'DRAFT');log(admin.id,'PAYOUT_DRAFT_CANCELLED',v);return ok({success:true});
 }
 return bad('Not found',404);
 }catch(e){if(e instanceof z.ZodError)return bad(e.issues.map(x=>`${x.path.join('.')}: ${x.message}`).join('; '));
 if(e instanceof Error && (e.message.includes('UNIQUE constraint')||e.message.includes('Insufficient')||e.message.includes('not found')))return bad(e.message);
 console.error(e);return bad('Server error',500);}
}
