'use strict';

var express=require('express'),jwt=require('jsonwebtoken'),bcrypt=require('bcryptjs'),cors=require('cors'),path=require('path'),fs=require('fs');
var app=express(),PORT=3002,SECRET='STARTECH_APP_2026',DATA=path.join(__dirname,'data','db.json');
app.use(cors());app.use(express.json());app.use(express.static(path.join(__dirname,'public')));

// 1 CRT = 50 FCFA
var CRT_PRICE=50;
var SERVICE_COST=10; // CRT par mois
var PLANS=[
  {id:'wg',name:'WireGuard VPN',desc:'Acces VPN WireGuard securise',cost:10,icon:'🔒'},
  {id:'mikhmon',name:'Mikhmon Online',desc:'Gestion hotspot MikroTik',cost:10,icon:'📡'},
  {id:'vpn',name:'Compte VPN',desc:'Compte VPN dedie',cost:10,icon:'👤'}
];
var PACKS=[
  {id:'p20',crt:20,fcfa:1000},
  {id:'p50',crt:50,fcfa:2500},
  {id:'p100',crt:100,fcfa:5000},
  {id:'p200',crt:200,fcfa:10000}
];

function db(){
  if(!fs.existsSync(DATA)){
    fs.mkdirSync(path.dirname(DATA),{recursive:true});
    var d={
      users:[{id:'u1',username:'admin',email:'admin@startech.com',password:bcrypt.hashSync('STARTECH2026',10),role:'admin',credits:100,gnx:50,createdAt:new Date().toISOString()}],
      routers:[],vpn_networks:[],vpn_accounts:[],scripts:[],transactions:[],services:[],payments:[]
    };
    fs.writeFileSync(DATA,JSON.stringify(d,null,2));
    return d;
  }
  return JSON.parse(fs.readFileSync(DATA,'utf8'));
}
function save(d){fs.writeFileSync(DATA,JSON.stringify(d,null,2));}
function auth(req,res,next){
  var h=req.headers['authorization'];
  if(!h)return res.status(401).json({error:'Token manquant'});
  try{req.user=jwt.verify(h.split(' ')[1],SECRET);next();}
  catch(e){res.status(401).json({error:'Token invalide'});}
}
function admin(req,res,next){if(req.user.role!=='admin')return res.status(403).json({error:'Acces refuse'});next();}

// AUTH
app.post('/api/auth/login',function(req,res){
  var d=db(),u=d.users.find(function(x){return x.username===req.body.username||x.email===req.body.username;});
  if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:'Identifiants incorrects'});
  var t=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:'24h'});
  res.json({token:t,user:{id:u.id,username:u.username,email:u.email,role:u.role,credits:u.credits,gnx:u.gnx}});
});

app.post('/api/auth/register',function(req,res){
  var d=db();
  if(!req.body.username||!req.body.password||!req.body.email)return res.status(400).json({error:'Champs requis manquants'});
  if(d.users.find(function(x){return x.username===req.body.username;}))return res.status(400).json({error:'Nom utilisateur deja pris'});
  if(d.users.find(function(x){return x.email===req.body.email;}))return res.status(400).json({error:'Email deja utilise'});
  var u={id:'u'+Date.now(),username:req.body.username,email:req.body.email,password:bcrypt.hashSync(req.body.password,10),role:'client',credits:0,gnx:0,createdAt:new Date().toISOString()};
  d.users.push(u);
  save(d);
  var t=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:'24h'});
  res.json({token:t,user:{id:u.id,username:u.username,email:u.email,role:u.role,credits:0,gnx:0}});
});

app.post('/api/auth/register-admin',auth,admin,function(req,res){
  var d=db();
  if(d.users.find(function(x){return x.username===req.body.username;}))return res.status(400).json({error:'Existant'});
  var u={id:'u'+Date.now(),username:req.body.username,email:req.body.email||'',password:bcrypt.hashSync(req.body.password,10),role:req.body.role||'client',credits:0,gnx:0,createdAt:new Date().toISOString()};
  d.users.push(u);save(d);
  res.json({success:true,user:{id:u.id,username:u.username,role:u.role}});
});

// DASHBOARD
app.get('/api/dashboard',auth,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  var myServices=d.services.filter(function(s){return s.userId===req.user.id;});
  res.json({
    stats:{routers:d.routers.length,vpn_networks:d.vpn_networks.length,vpn_accounts:d.vpn_accounts.length,scripts:d.scripts.length,users:d.users.length,transactions:d.transactions.length,services:d.services.length},
    user:{credits:u?u.credits:0,gnx:u?u.gnx:0},
    myServices:myServices
  });
});

// PLANS & PACKS
app.get('/api/plans',function(req,res){res.json(PLANS);});
app.get('/api/packs',function(req,res){res.json(PACKS);});

// ACHETER SERVICE
app.post('/api/services/buy',auth,function(req,res){
  var d=db();
  var u=d.users.find(function(x){return x.id===req.user.id;});
  if(!u)return res.status(404).json({error:'Utilisateur introuvable'});
  var plan=PLANS.find(function(p){return p.id===req.body.planId;});
  if(!plan)return res.status(400).json({error:'Plan introuvable'});
  var months=parseInt(req.body.months)||1;
  var cost=plan.cost*months;
  if(u.credits<cost)return res.status(400).json({error:'Credits insuffisants. Vous avez '+u.credits+' CRT, il faut '+cost+' CRT'});
  u.credits-=cost;
  var expiry=new Date();
  expiry.setMonth(expiry.getMonth()+months);
  var svc={
    id:'svc'+Date.now(),
    userId:u.id,
    planId:plan.id,
    planName:plan.name,
    months:months,
    cost:cost,
    status:'active',
    expiry:expiry.toISOString(),
    createdAt:new Date().toISOString(),
    details:{}
  };
  if(!d.services)d.services=[];
  d.services.push(svc);
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'achat_service',amount:-cost,note:plan.name+' x'+months+'mois',date:new Date().toISOString()});
  save(d);
  res.json({success:true,service:svc,creditsLeft:u.credits});
});

// MES SERVICES
app.get('/api/services/mine',auth,function(req,res){
  var d=db();
  var svcs=d.services?d.services.filter(function(s){return s.userId===req.user.id;}):[]; 
  res.json(svcs);
});

app.get('/api/services',auth,admin,function(req,res){
  var d=db();
  res.json(d.services||[]);
});

// RECHARGE CREDITS (admin manuel)
app.post('/api/users/:id/credits',auth,admin,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.params.id;});
  if(!u)return res.status(404).json({error:'Introuvable'});
  u.credits+=parseInt(req.body.amount)||0;
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'recharge',amount:parseInt(req.body.amount)||0,note:req.body.note||'Recharge admin',date:new Date().toISOString()});
  save(d);res.json({success:true,credits:u.credits});
});

// PAIEMENT FEDAPAY (initier)
app.post('/api/payment/init',auth,function(req,res){
  var pack=PACKS.find(function(p){return p.id===req.body.packId;});
  if(!pack)return res.status(400).json({error:'Pack introuvable'});
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  // Simuler paiement en attente
  var payment={id:'pay'+Date.now(),userId:u.id,packId:pack.id,crt:pack.crt,fcfa:pack.fcfa,status:'pending',createdAt:new Date().toISOString()};
  if(!d.payments)d.payments=[];
  d.payments.push(payment);
  save(d);
  res.json({paymentId:payment.id,amount:pack.fcfa,crt:pack.crt,fedapayUrl:'https://sandbox.fedapay.com/checkout/'+payment.id});
});

// CONFIRMER PAIEMENT (webhook ou manuel admin)
app.post('/api/payment/confirm/:id',auth,admin,function(req,res){
  var d=db();
  if(!d.payments)return res.status(404).json({error:'Aucun paiement'});
  var pay=d.payments.find(function(p){return p.id===req.params.id;});
  if(!pay)return res.status(404).json({error:'Paiement introuvable'});
  if(pay.status==='confirmed')return res.status(400).json({error:'Deja confirme'});
  var u=d.users.find(function(x){return x.id===pay.userId;});
  if(!u)return res.status(404).json({error:'Utilisateur introuvable'});
  pay.status='confirmed';
  u.credits+=pay.crt;
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'recharge',amount:pay.crt,note:'Paiement '+pay.fcfa+' FCFA',date:new Date().toISOString()});
  save(d);
  res.json({success:true,credits:u.credits});
});

// PAIEMENTS LISTE (admin)
app.get('/api/payments',auth,admin,function(req,res){
  var d=db();res.json(d.payments||[]);
});

// USERS
app.get('/api/users',auth,admin,function(req,res){
  var d=db();
  res.json(d.users.map(function(u){return{id:u.id,username:u.username,email:u.email,role:u.role,credits:u.credits,gnx:u.gnx,createdAt:u.createdAt};}));
});

// TRANSACTIONS
app.get('/api/transactions',auth,function(req,res){
  var d=db(),t=req.user.role==='admin'?d.transactions:d.transactions.filter(function(x){return x.userId===req.user.id;});
  res.json(t);
});

// ROUTERS
app.get('/api/routers',auth,function(req,res){res.json(db().routers);});
app.post('/api/routers',auth,function(req,res){
  var d=db(),r={id:'r'+Date.now(),name:req.body.name,ip:req.body.ip,port:req.body.port||8728,username:req.body.username||'admin',password:req.body.password||'',ownerId:req.user.id,expiry:req.body.expiry||null,createdAt:new Date().toISOString()};
  d.routers.push(r);save(d);res.json(r);
});
app.delete('/api/routers/:id',auth,function(req,res){
  var d=db();d.routers=d.routers.filter(function(r){return r.id!==req.params.id;});save(d);res.json({success:true});
});

// WG
app.get('/api/wg/networks',auth,function(req,res){res.json(db().vpn_networks);});
app.post('/api/wg/networks',auth,function(req,res){
  var d=db(),n={id:'wg'+Date.now(),name:req.body.name,subnet:req.body.subnet||'10.8.0.0/24',port:req.body.port||51820,ownerId:req.user.id,devices:[],createdAt:new Date().toISOString()};
  d.vpn_networks.push(n);save(d);res.json(n);
});

// VPN ACCOUNTS
app.get('/api/vpn/accounts',auth,function(req,res){
  var d=db(),a=req.user.role==='admin'?d.vpn_accounts:d.vpn_accounts.filter(function(x){return x.ownerId===req.user.id;});
  res.json(a);
});
app.post('/api/vpn/accounts',auth,function(req,res){
  var d=db(),a={id:'vpn'+Date.now(),username:req.body.username,plan:req.body.plan||'1mois',price:req.body.price||500,expiry:req.body.expiry,ownerId:req.user.id,status:'active',createdAt:new Date().toISOString()};
  d.vpn_accounts.push(a);save(d);res.json(a);
});

// SCRIPTS
app.get('/api/scripts',auth,function(req,res){res.json(db().scripts);});
app.post('/api/scripts',auth,admin,function(req,res){
  var d=db(),s={id:'s'+Date.now(),name:req.body.name,description:req.body.description||'',category:req.body.category||'general',code:req.body.code||'',cost:req.body.cost||0,createdAt:new Date().toISOString()};
  d.scripts.push(s);save(d);res.json(s);
});

app.get('/{*path}',function(req,res){res.sendFile(path.join(__dirname,'public','index.html'));});
app.listen(PORT,function(){console.log('Startech App port '+PORT);});
