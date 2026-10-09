(() => {
 const hero=document.querySelector('.home-hero');
 const art=document.querySelector('.home-art');
 const layers=[...document.querySelectorAll('[data-depth]')];
 const mobile=matchMedia('(max-width:700px)');
 const pointer=matchMedia('(hover:hover) and (pointer:fine)');
 const reduced=matchMedia('(prefers-reduced-motion:reduce)');
 let tx=0,ty=0,x=0,y=0,frame=0;
 function render(){
  frame=0;
  if(reduced.matches){art.style.removeProperty('--scroll-x');layers.forEach(el=>{el.style.removeProperty('--mx');el.style.removeProperty('--my')});return;}
  if(mobile.matches){const r=hero.getBoundingClientRect();const progress=Math.max(0,Math.min(1,-r.top/Math.max(1,r.height-innerHeight*.3)));art.style.setProperty('--scroll-x',(progress*65)+'px');}
  else{art.style.removeProperty('--scroll-x');x+=(tx-x)*.09;y+=(ty-y)*.09;layers.forEach(el=>{const d=Number(el.dataset.depth);el.style.setProperty('--mx',(x*d)+'px');el.style.setProperty('--my',(y*d)+'px')});if(Math.abs(tx-x)+Math.abs(ty-y)>.002)queue();}
 }
 function queue(){if(!frame)frame=requestAnimationFrame(render)}
 hero.addEventListener('pointermove',e=>{if(!pointer.matches||mobile.matches||reduced.matches)return;const r=hero.getBoundingClientRect();tx=(e.clientX-r.left)/r.width*2-1;ty=(e.clientY-r.top)/r.height*2-1;queue()});
 hero.addEventListener('pointerleave',()=>{tx=ty=0;queue()});
 addEventListener('scroll',()=>{if(mobile.matches)queue()},{passive:true});
 addEventListener('resize',()=>{tx=ty=x=y=0;queue()},{passive:true});
 reduced.addEventListener('change',queue);queue();
})();
