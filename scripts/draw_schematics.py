"""Vector drawing primitives; copied into each independent project generator."""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)

NAMES=('contract','cut','density')
def draw_all(out):
    out.mkdir(parents=True,exist_ok=True)
    d=Drawing((-1.95,-2.45,13.1,2.45))
    d.box('events',0,.85,3.6,1.2,'Shared events\nand mask promise')
    d.box('maps',0,-.85,3.6,1.2,'Source and target\nresidencies')
    d.box('admit',4,0,2.8,1.2,'Admission\nand codecs')
    d.box('sig',7.55,0,3.0,1.2,'Exact signed\nOR difference')
    d.box('eq',11.15,1.2,3.6,1.2,'Squared-count\nequality')
    d.box('ub',11.15,-1.2,3.6,1.2,'Frontier-potential\nupper bound')
    d.edge('events','admit','e','w')
    d.edge('maps','admit','e','w')
    d.edge('admit','sig','e','w')
    d.edge('sig','eq','e','w')
    d.edge('sig','ub','e','w')
    d.save(out,'contract')
    d=Drawing((-3.0,-2.0,9.3,4.2))
    for x,g in enumerate(('u','u','v','v')):
        d.box('s'+str(x),.9*x+.45,2.45,.9,.7,'$'+g+'$')
    for x,g in enumerate(('u','v','u','v')):
        d.box('t'+str(x),.9*x+.45,.35,.9,.7,'$'+g+'$')
    for x,label in ((.9,r'$4x_u$'),(2.7,r'$4x_v$')):
        d.box('sb'+str(x),x,3.15,1.8,.7,label)
        d.box('tb'+str(x),x,-.35,1.8,.7,r'$4\mathrm{OR}_{uv}$')
    for y,label in ((3.15,r'$B$ residency'),(2.45,'source guards'),(.35,'target guards'),(-.35,r'$B$ residency')):
        d.text(-.3,y,label,ha='right')
    d.arrow((1.35,2.1),(2.25,.7))
    d.arrow((2.25,2.1),(1.35,.7))
    d.text(4.4,2.1,'One $A$ word and one $B$ word\nlive at a time.',ha='left')
    d.text(4.4,.8,'Only the middle event identities\ninterchange.',ha='left')
    d.text(1.8,-1.35,r'$\Delta B=8\mathrm{OR}_{uv}-4x_u-4x_v=4(x_u\oplus x_v)$')
    d.save(out,'cut')
    d=Drawing((-.5,-1.8,8.1,4.35))
    for left in (0,4.7):
        for k in range(5):
            v=k*.65
            d.line([(left+v,0),(left+v,2.6)])
            d.line([(left,v),(left+2.6,v)])
    for k in range(4):
        d.ax.plot((k+.5)*.65,2.5*.65,'ko',markersize=3.5)
        d.ax.plot(4.7+1.5*.65,(k+.5)*.65,'ko',markersize=3.5)
    d.text(1.3,3.45,r'$B$ bytes: $4\rightarrow16$'+'\n'+r'$\Delta B=+12$')
    d.text(6.0,3.45,r'$B$ bytes: $16\rightarrow4$'+'\n'+r'$\Delta B=-12$')
    d.text(1.3,-.55,'one active row')
    d.text(6.0,-.55,'one active column')
    d.text(3.65,-1.25,'Filled dot: present guard. Both masks have density $1/4$.')
    d.save(out,'density')
def main():
    import tempfile
    ap=argparse.ArgumentParser(description='Direct Python vector drawings of the sparse-mapping contract, cut gadget and density witness.')
    ap.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'figures')
    ap.add_argument('--check',action='store_true')
    a=ap.parse_args()
    if a.check:
        with tempfile.TemporaryDirectory() as td:
            out=Path(td);draw_all(out)
            for name in NAMES:
                if not (a.output/(name+'.pdf')).is_file() or (a.output/(name+'.pdf')).read_bytes()!=(out/(name+'.pdf')).read_bytes():
                    raise SystemExit('Missing/stale schematic: '+name)
        print('All three schematics reproduce byte-for-byte.')
    else:draw_all(a.output)
if __name__=='__main__':main()
