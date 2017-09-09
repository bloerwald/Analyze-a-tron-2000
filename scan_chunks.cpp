#include <iostream>
#include <map>
#include <set>

#include "util/file.hpp"
#include "util/iffchunk.hpp"
#include "util/insert_order_collections.hpp"
#include "util/string.hpp"

int main (int argc, char** argv)
try
{
	for (auto&& filename : std::vector<std::string> {argv + 1, argv + argc})
	{
    bool const is_flipped (util::has_suffix (filename, {"wmo", "adt"}));

    std::cout << filename << "\n";

		util::file_t const file (filename);
		util::iffchunk const* iter (reinterpret_cast<util::iffchunk const*> (file.data.data()));

    static std::map<uint32_t, std::set<uint32_t>> const known_chunks
      { {'MVER', {}}

      // .adt
      , {'MHDR', {}}
      , {'MCIN', {}}
      , {'MTEX', {}}
      , {'MMDX', {}}
      , {'MMID', {}}
      , {'MWMO', {}}
      , {'MWID', {}}
      , {'MDDF', {}}
      , {'MODF', {}}
      , {'MH2O', {}}
      , {'MCNK', { 'MCVT'
                 , 'MCLV'
                 , 'MCCV'
                 , 'MCNR'
                 , 'MCLY'
                 , 'MCRF'
                 , 'MCRD'
                 , 'MCRW'
                 , 'MCSH'
                 , 'MCAL'
                 , 'MCLQ'
                 , 'MCSE'
                 , 'MCBB'
                 , 'MCMT'
                 , 'MCDD'
                 }
        }
      , {'MFBO', {}}
      , {'MTXF', {}}
      , {'MTXP', {}}
      , {'MBMH', {}}
      , {'MBBB', {}}
      , {'MBNV', {}}
      , {'MBMI', {}}
      , {'MAMP', {}}
      , {'MLHD', {}}
      , {'MLVH', {}}
      , {'MLVI', {}}
      , {'MLLL', {}}
      , {'MLND', {}}
      , {'MLSI', {}}
      , {'MLLD', {}}
      , {'MLLN', {}}
      , {'MLLV', {}}
      , {'MLLI', {}}
      , {'MLMD', {}}
      , {'MLMX', {}}
      , {'MLDD', {}}
      , {'MLDX', {}}
      , {'MLDL', {}}
      , {'MLFD', {}}
      , {'MBMB', {}}

      // .wdt
      , {'MPHD', {}}
      , {'MAIN', {}}
      , {'MWMO', {}}
      , {'MODF', {}}
      // _occ.wdt
      , {'MAOI', {}}
      , {'MAOH', {}}
      // _lgt.wdt
      , {'MPLT', {}}
      , {'MPL2', {}}
      , {'MSLT', {}}
      , {'MTEX', {}}
      , {'MLTA', {}}

      // .wdl
      , {'MAOF', {}}
      , {'MARE', {}}
      , {'MAOC', {}}
      , {'MAOE', {}}
      , {'MAHO', {}}

      // .m2
      , {util::reversed ('MD21'), {}}
      , {util::reversed ('PFID'), {}}
      , {util::reversed ('SFID'), {}}
      , {util::reversed ('AFID'), {}}
      , {util::reversed ('BFID'), {}}
      , {util::reversed ('MD21'), {}}
      , {util::reversed ('TXAC'), {}}
      , {util::reversed ('EXPT'), {}}
      , {util::reversed ('EXP2'), {}}
      , {util::reversed ('PABC'), {}}
      , {util::reversed ('PADC'), {}}
      , {util::reversed ('PSBC'), {}}
      , {util::reversed ('PEDC'), {}}
      , {util::reversed ('SKID'), {}}

      // .anim
      , {util::reversed ('AFM2'), {}}
      , {util::reversed ('AFSA'), {}}
      , {util::reversed ('AFSB'), {}}

      // .skel
      , {util::reversed ('SKA1'), {}}
      , {util::reversed ('SKB1'), {}}
      , {util::reversed ('SKL1'), {}}
      , {util::reversed ('SKPD'), {}}
      , {util::reversed ('SKS1'), {}}
      , {util::reversed ('AFID'), {}}
      , {util::reversed ('BFID'), {}}

      // .phys
      , {'PHYS', {}}
      , {'PHYV', {}}
      , {'PHYT', {}}
      , {'BODY', {}}
      , {'BDY2', {}}
      , {'BDY3', {}}
      , {'BDY4', {}}
      , {'SHAP', {}}
      , {'SHP2', {}}
      , {'BOXS', {}}
      , {'CAPS', {}}
      , {'SPHS', {}}
      , {'PLYT', {}}
      , {'JOIN', {}}
      , {'WELJ', {}}
      , {'WLJ2', {}}
      , {'SPHJ', {}}
      , {'SHOJ', {}}
      , {'PRSJ', {}}
      , {'REVJ', {}}
      , {'DSTJ', {}}

      // World.def
      , {'DMAP', {}}

      // .tex
      , {'TXVR', {}}
      , {'TXBT', {}}
      , {'TXFN', {}}
      , {'TXMD', {}}

      // .bone
      , {'BIDA', {}}
      , {'BOMT', {}}

      // root .wmo
      , {'MOMO', {}} // actually all other wmo root chunks as members
      , {'MOHD', {}}
      , {'MOTX', {}}
      , {'MOMT', {}}
      , {'MOUV', {}}
      , {'MOGN', {}}
      , {'MOGI', {}}
      , {'MOSB', {}}
      , {'MOPV', {}}
      , {'MOPT', {}}
      , {'MOPR', {}}
      , {'MOVV', {}}
      , {'MOVB', {}}
      , {'MOLT', {}}
      , {'MODS', {}}
      , {'MODN', {}}
      , {'MODD', {}}
      , {'MFOG', {}}
      , {'MCVP', {}}
      , {'GFID', {}}

      // group .wmo
      , {'MOGP', { 'MOPY'
                 , 'MOVI'
                 , 'MOVT'
                 , 'MONR'
                 , 'MOTV'
                 , 'MOLV'
                 , 'MOIN'
                 , 'MOBA'
                 , 'MOLR'
                 , 'MODR'
                 , 'MOBN'
                 , 'MOBR'
                 , 'MOCV'
                 , 'MLIQ'
                 , 'MORI'
                 , 'MORB'
                 , 'MOTA'
                 , 'MOBS'
                 , 'MDAL'
                 , 'MOPL'
                 , 'MOPB'
                 , 'MOLS'
                 , 'MOLP'
                 , 'MOLM'
                 , 'MOLD'
                 }
        }
      };
    util::insert_order_map<uint32_t, util::insert_order_set<uint32_t>> seen_chunks;

    for (; iter != file.end(); iter = iter->next())
    {
      auto& sub (seen_chunks[iter->magic]);
      if (iter->magic == 'MOGP' || iter->magic == 'MCNK' || iter->magic == 'MOMO')
      {
        util::iffchunk const* sub_iter 
          ( iter->sub ( iter->magic == 'MOGP' ? 0x44
                      : iter->magic == 'MOMO' ? 0x00
                      : iter->magic == 'MCNK' ? 
                          ( util::has_suffix (filename, {"_obj0.adt", "_obj1.adt", "_tex0.adt", "_tex1.adt"}) 
                          ? 0x0 
                          : 0x80
                          )
                      : throw std::logic_error ("")
                      )
          );
        util::iffchunk const* sub_iter_end (iter->next());

        for (; sub_iter != sub_iter_end; sub_iter = sub_iter->next())
        {
          sub.emplace (sub_iter->magic);
        }
      }
    }

    for (auto const& seen : seen_chunks)
    {
      std::cout << util::readable_magic (seen.first, is_flipped);
      if (!known_chunks.count (seen.first))
      {
        std::cout << " which appears to be new!";
      }
      std::cout << "\n";
      for (auto const& sub : seen.second)
      {
        std::cout << "  " << util::readable_magic (sub, is_flipped);
        if (!known_chunks.count (seen.first) || !known_chunks.at (seen.first).count (sub))
        {
          std::cout << " which appears to be new!";
        }
        std::cout << "\n";
      }
    }
	}

	return 0;
}
catch (std::exception const& ex)
{
	std::cerr << ex.what() << "\n";
	return 1;
}
