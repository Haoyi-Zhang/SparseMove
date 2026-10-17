"""Draw the two retained numeric plots directly as embedded-font vector PDFs.

Reads CSV results only; it never runs the analyzer, solver, or a benchmark.
Install the existing requirements-schematics.txt dependencies before use.
"""
from pathlib import Path
import argparse
import csv
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
WIDTH, HEIGHT = 427.05, 209.2545
BOX = [62 / WIDTH, 38 / HEIGHT, (420 - 62) / WIDTH, (202 - 38) / HEIGHT]


def data(directory):
    with (directory / 'equality-plot.csv').open(newline='', encoding='utf-8-sig') as f:
        equality = list(csv.DictReader(f))
    with (directory / 'cliques.csv').open(newline='', encoding='utf-8-sig') as f:
        cliques = list(csv.DictReader(f))
    if [int(r['groups']) for r in equality] != [1, 2, 4, 8, 16, 32, 64, 128]:
        raise ValueError('Unexpected completed equality rows')
    for r in equality:
        value = float(r['median_seconds'])
        if r['status'] != 'equal' or not math.isfinite(value) or value <= 0:
            raise ValueError('Only completed positive equality timings may be drawn')
        if not float(r['min_seconds']) <= value <= float(r['max_seconds']):
            raise ValueError('Median is outside the retained timing range')
    if [int(r['vertices']) for r in cliques] != list(range(3, 13)):
        raise ValueError('Unexpected clique rows')
    if any(r['status'] != 'certified' or not 0 <= int(r['joint_bound']) <= int(r['sum_local_bounds']) for r in cliques):
        raise ValueError('Uncertified or inconsistent bound row')
    return equality, cliques


def canvas():
    fig = plt.figure(figsize=(WIDTH / 72, HEIGHT / 72))
    ax = fig.add_axes(BOX)
    ax.tick_params(direction='out', width=.55, length=3, labelsize=9, pad=3)
    for spine in ax.spines.values():
        spine.set_linewidth(.55)
    ax.grid(axis='y', color='.87', linewidth=.35)
    ax.set_axisbelow(True)
    return fig, ax


def save(fig, path):
    fig.savefig(path, metadata={'Creator': 'Python Matplotlib', 'Producer': None,
                               'CreationDate': None, 'ModDate': None})
    plt.close(fig)


def draw(directory, output):
    equality, cliques = data(directory)
    plt.rcParams.update({'font.family': 'STIXGeneral', 'mathtext.fontset': 'stix',
                         'font.size': 9, 'pdf.fonttype': 42, 'ps.fonttype': 42,
                         'text.usetex': False, 'axes.unicode_minus': False})
    output.mkdir(parents=True, exist_ok=True)
    fig, ax = canvas()
    x = [int(r['groups']) for r in equality]
    y = [float(r['median_seconds']) for r in equality]
    line, = ax.plot(x, y, '-o', color='black', markersize=4, linewidth=.65,
                    markeredgewidth=.45, label='Median of three runs')
    if list(line.get_xdata()) != x or list(line.get_ydata()) != y:
        raise AssertionError('Equality plot changed a retained value')
    ax.set_xscale('log', base=2)
    ax.set_yscale('log', base=10)
    ax.set(xlim=(.8, 160), ylim=(10 ** -5.2, 10 ** 1.05))
    ax.set_xticks(x, [str(v) for v in x])
    ax.set_yticks([10 ** p for p in range(-5, 1)])
    ax.minorticks_off()
    ax.set_xlabel('Independent exact 2:4 blocks', labelpad=5)
    ax.set_ylabel('Squared-sum phase (seconds)', labelpad=5)
    ax.legend(loc='upper left', frameon=True, facecolor='white', edgecolor='none',
              framealpha=1, borderpad=.4, handlelength=2, fontsize=9)
    save(fig, output / 'equality.pdf')

    fig, ax = canvas()
    x = [int(r['vertices']) for r in cliques]
    for key, label, style, marker, gray in [
        ('sum_local_bounds', 'Sum of local edge maxima', '--', 's', '.3'),
        ('joint_bound', 'Joint certified maximum', '-', 'o', '0'),
    ]:
        y = [int(r[key]) for r in cliques]
        line, = ax.plot(x, y, linestyle=style, marker=marker, color=gray,
                        linewidth=.65, markersize=4, markeredgewidth=.45, label=label,
                        clip_on=False)
        if list(line.get_xdata()) != x or list(line.get_ydata()) != y:
            raise AssertionError('Bound plot changed a retained value')
    ax.set(xlim=(3, 12), ylim=(0, 280))
    ax.set_xticks(x)
    ax.set_yticks([0, 50, 100, 150, 200, 250])
    ax.set_xlabel('Vertices in complete graph', labelpad=5)
    ax.set_ylabel('Upper bound on byte difference', labelpad=5)
    ax.legend(loc='upper left', frameon=True, facecolor='white', edgecolor='none',
              framealpha=1, borderpad=.4, handlelength=2, fontsize=9)
    save(fig, output / 'cliques.pdf')
    return {'completed_equality_rows': len(equality), 'certified_bound_rows': len(cliques)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--data', type=Path, default=ROOT / 'results')
    ap.add_argument('--output', type=Path, default=ROOT / 'figures')
    args = ap.parse_args()
    print(draw(args.data, args.output))


if __name__ == '__main__':
    main()
