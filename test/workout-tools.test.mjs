import { test } from 'node:test';
import assert from 'node:assert/strict';
import {executeWorkoutTool, workoutTools} from '../dist/workout-tools.js';

test('set logging sends the canonical command with retry identity and revision',async()=>{
 let call;
 const input={session_id:42,expected_revision:3,set_id:'set-1',reps:8,weight:135,client_id:'retry-id'};
 await executeWorkoutTool('log_workout_set',input,async(...args)=>{call=args;return {revision:4}});
 assert.deepEqual(call,['/workout_sessions/42/command','POST',{expected_revision:3,set_id:'set-1',reps:8,weight:135,client_id:'retry-id',type:'confirm_set'}]);
 assert.equal(input.session_id,42);
});
test('history filters are encoded and unknown tools fall through',async()=>{
 let path;
 await executeWorkoutTool('list_workout_sessions',{start_date:'2026-10-01',limit:10},async p=>{path=p;return []});
 assert.equal(path,'/workout_sessions?start_date=2026-10-01&limit=10');
 assert.equal(await executeWorkoutTool('unrelated',{},async()=>{}),undefined);
 assert.equal(new Set(workoutTools.map(t=>t.name)).size,37);
});
test('removing pending work keeps scoped command identity and revision',async()=>{
 for (const [name,type,extra] of [['remove_workout_session_set','remove_set',{set_id:'set-2'}],['remove_workout_session_move','remove_move',{move_id:'bench'}]]) {
  let call;
  await executeWorkoutTool(name,{session_id:42,expected_revision:3,client_id:'remove-retry',...extra},async(...args)=>{call=args;return {revision:4}});
  assert.deepEqual(call,['/workout_sessions/42/command','POST',{expected_revision:3,client_id:'remove-retry',...extra,type}]);
 }
});
test('variation updates preserve an empty clear and use numeric library IDs',async()=>{
 let call;
 await executeWorkoutTool('update_workout_move',{move_id:7,variation_ids:[]},async(...args)=>{call=args;return {}});
 assert.deepEqual(call,['/workout_moves/7','PATCH',{variation_ids:[]}]);
 assert.equal(workoutTools.find(t=>t.name==='update_workout_move').inputSchema.properties.variation_ids.type,'array');
});
test('return to rest and swap send canonical atomic commands',async()=>{
 for (const [name,type,extra] of [['return_to_workout_rest','return_to_rest',{}],['replace_workout_session_move','replace_move',{move_id:'bench',move:{name:'Chest Press',sets:[{reps_min:6,reps_max:8,weight:80,rest_seconds:90}]}}]]) {
  let call;
  await executeWorkoutTool(name,{session_id:42,expected_revision:3,client_id:'retry',...extra},async(...args)=>{call=args;return {revision:4}});
  assert.deepEqual(call,['/workout_sessions/42/command','POST',{expected_revision:3,client_id:'retry',...extra,type}]);
 }
});
test('cancel and delete preserve revision checks and command retry IDs',async()=>{
 for (const type of ['cancel','delete']) {
  let call;
  await executeWorkoutTool(`${type}_workout_session`,{session_id:42,expected_revision:3,client_id:`${type}-retry`},async(...args)=>{call=args;return {revision:4}});
  assert.deepEqual(call,['/workout_sessions/42/command','POST',{expected_revision:3,client_id:`${type}-retry`,type}]);
 }
});
test('notes commands retain empty clears, line breaks and retry identity',async()=>{
 for (const [name,type,extra] of [['set_workout_session_notes','set_notes',{notes:''}],['set_workout_move_notes','set_move_notes',{move_id:'bench',notes:'Seat 4\nSlow eccentric'}]]) {
  let call;
  await executeWorkoutTool(name,{session_id:42,expected_revision:3,client_id:'notes-retry',...extra},async(...args)=>{call=args;return {revision:4}});
  assert.deepEqual(call,['/workout_sessions/42/command','POST',{expected_revision:3,client_id:'notes-retry',...extra,type}]);
 }
});
test('performance reads use scoped resources and session cursor pagination',async()=>{
 let call;
 await executeWorkoutTool('get_workout_move_performance',{move_id:7,limit:30,before_id:42},async(...args)=>{call=args;return {}});
 assert.deepEqual(call,['/workout_moves/7/performance?limit=30&before_id=42']);
 await executeWorkoutTool('get_workout_session_performance',{session_id:42},async(...args)=>{call=args;return {}});
 assert.deepEqual(call,['/workout_sessions/42/performance']);
});
