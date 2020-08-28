#include <retdec/pelib/PeLib.h>

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

struct RawFile
{
  RawFile (std::string const& path, char const* mode)
    : handle (fopen (path.c_str(), mode))
  {
    if (!handle) throw std::invalid_argument ("failed open " + path + " m=" + mode);
  }
  ~RawFile()
  {
    fclose (handle);
  }

  std::size_t size() const
  {
    auto const curr (ftell (handle));
    fseek (handle, 0, SEEK_END);
    auto const result (ftell (handle));
    fseek (handle, curr, SEEK_SET);
    return result;
  }

  void copy_from (RawFile const& source)
  {
    std::vector<char> data (source.size());
    source.seek (0, SEEK_SET);
    source.read (data.data(), data.size());
    seek (0, SEEK_SET);
    write (data.data(), data.size());
  }

  void copy_from (RawFile const& source, std::size_t offs, std::size_t size)
  {
    std::vector<char> data (size);
    source.seek (offs, SEEK_SET);
    source.read (data.data(), data.size());
    seek (offs, SEEK_SET);
    write (data.data(), data.size());
  }

  template<typename T>
    T read (std::size_t offs) const
  {
    seek (offs, SEEK_SET);
    T res;
    read (&res, sizeof (res));
    return res;
  }
  template<typename T>
    void write (std::size_t offs, T what)
  {
    seek (offs, SEEK_SET);
    write (&what, sizeof (what));
  }

  std::vector<char> read (std::size_t offs, std::size_t size) const
  {
    std::vector<char> blob (size);
    seek (offs, SEEK_SET);
    read (blob.data(), blob.size());
    return blob;
  }

  void insert (std::size_t offs, std::vector<char> const& data)
  {
    std::vector<char> rest (size() - offs);
    seek (offs, SEEK_SET);
    read (rest.data(), rest.size());
    seek (offs, SEEK_SET);
    write (data.data(), data.size());
    write (rest.data(), rest.size());
  }

private:
  void seek (std::size_t offs, int whence) const
  {
    if (fseek (handle, offs, whence) != 0) throw std::runtime_error ("failed seek");
  }
  void read (void* dest, std::size_t size) const
  {
    if (fread (dest, size, 1, handle) != 1) throw std::runtime_error ("failed reading");
  }
  void write (void const* src, std::size_t size)
  {
    if (fwrite (src, size, 1, handle) != 1) throw std::runtime_error ("failed writing");
  }

  FILE* handle;
};

struct PEFile
{
  std::string fn;
  PeLib::PeFile64 pef;
  PeLib::PeHeader64& peh;
  PeLib::RelocationsDirectory& relocs;
  PeLib::ImportDirectory64& imports;

  std::size_t text_index = -1;
  std::size_t rdata_index = -1;
  std::size_t SCY_index = -1;

  PEFile (std::string f, bool dont_read_directories = false)
    : fn (f)
    , pef (fn)
    , peh (pef.peHeader())
    , relocs (pef.relocDir())
    , imports (pef.impDir())
  {
    if (pef.readMzHeader()) throw std::logic_error ("failed read mz " + fn);
    if (pef.readPeHeader()) throw std::logic_error ("failed read pe " + fn);
    if (!dont_read_directories)
    {
      if (pef.readRelocationsDirectory()) throw std::logic_error ("failed read relocs " + fn);
      if (pef.readImportDirectory()) throw std::logic_error ("failed read imports " + fn);
    }

    for (std::size_t i (0); i < peh.getNumberOfSections(); ++i)
    {
      if (peh.getSectionName (i) == ".text")
      {
        text_index = i;
      }
      else if (peh.getSectionName (i) == ".rdata")
      {
        rdata_index = i;
      }
      else if (peh.getSectionName (i) == ".SCY")
      {
        SCY_index = i;
      }
    }
  }
};

int main(int argc, char** argv)
try
{
  if (argc != 4)
  {
    throw std::invalid_argument (std::string (argv[0]) + " obfuscated dumped output");
  }

  // Keep scope of PEFiles small to avoid writing to raw file and not
  // re-reading or alike. NEVER have a non-const PEFile and a
  // non-const RawFile in the same scope!
  struct Main
  {
    std::string const obfuscated;
    std::string const dumped;
    std::string const output;

    Main (std::string ob, std::string d, std::string ou)
      : obfuscated (ob), dumped (d), output (ou)
    {
      PEFile const pef_obfuscated (obfuscated);
      PEFile const pef_dumped (dumped);

      if (pef_obfuscated.relocs.calcNumberOfRelocations() != pef_dumped.relocs.calcNumberOfRelocations())
      {
        throw std::logic_error ("number of relocs differs?!");
      }
      for (std::size_t i (0); i < pef_obfuscated.relocs.calcNumberOfRelocations(); ++i)
      {
        if (pef_obfuscated.relocs.calcNumberOfRelocationData (i) != pef_dumped.relocs.calcNumberOfRelocationData (i))
        {
          throw std::logic_error ("number of relocs differs?!");
        }
      }

      if (pef_obfuscated.text_index != pef_dumped.text_index) throw std::logic_error (".text index differs");
      if (pef_obfuscated.rdata_index != pef_dumped.rdata_index) throw std::logic_error (".rdata index differs");
    }

    void prepare_output_from_obfuscated() const
    {
      RawFile const file_obfuscated (obfuscated, "rb");
      RawFile file_output (output, "w+b");

      file_output.copy_from (file_obfuscated);
    }

    void decrypt_text_segment()
    {
      RawFile const file_obfuscated (obfuscated, "rb");
      PEFile const pef_obfuscated (obfuscated);
      RawFile const file_dumped (dumped, "rb");
      PEFile const pef_dumped (dumped);
      RawFile file_output (output, "r+b");

      file_output.copy_from
        ( file_dumped
        , pef_dumped.peh.getPointerToRawData (pef_dumped.text_index)
        , pef_obfuscated.peh.getSizeOfRawData (pef_obfuscated.text_index)
        );
    }

    void fix_relocations() const
    {
      RawFile const file_obfuscated (obfuscated, "rb");
      PEFile const pef_obfuscated (obfuscated);
      RawFile const file_dumped (dumped, "rb");
      PEFile const pef_dumped (dumped);
      RawFile file_output (output, "r+b");

      auto const obfuscated_ib (pef_obfuscated.peh.getImageBase());
      auto const dumped_ib (pef_dumped.peh.getImageBase());
      auto const reloc_dist (dumped_ib - obfuscated_ib);

      for (std::size_t i (0); i < pef_obfuscated.relocs.calcNumberOfRelocations(); ++i)
      {
        auto const vbase_obfuscated (pef_obfuscated.relocs.getVirtualAddress (i));
        auto const vbase_dumped (pef_dumped.relocs.getVirtualAddress (i));
        for (size_t j (0); j < pef_obfuscated.relocs.calcNumberOfRelocationData (i); ++j)
        {
          auto const data_obfuscated (pef_obfuscated.relocs.getRelocationData(i, j));
          auto const data_dumped (pef_dumped.relocs.getRelocationData(i, j));
          if (data_obfuscated != data_dumped) throw std::logic_error ("differing reloc data?!");

          auto const method ((data_obfuscated & 0xF000) >> (4 * 3));
          if (method == 0) continue;
          else if (method != 0xA) throw std::logic_error ("unknown reloc method " + std::to_string (method));

          auto const offs (data_obfuscated & 0x0FFF);
          auto const rva_obfuscated (vbase_obfuscated + offs);
          auto const rva_dumped (vbase_dumped + offs);
          auto const foffs_obfuscated (pef_obfuscated.peh.rvaToOffset (rva_obfuscated));
          auto const foffs_dumped (pef_dumped.peh.rvaToOffset (rva_dumped));

          if (foffs_dumped != foffs_obfuscated) throw std::logic_error ("foffs diff?!");

          // .text is encrypted: believe the dumped one
          if (pef_obfuscated.text_index == pef_obfuscated.peh.getSectionWithRva (rva_obfuscated))
          {
            file_output.write<std::uint64_t>
              (foffs_obfuscated, file_dumped.read<std::uint64_t> (foffs_dumped) - reloc_dist);
          }
          // remainder is fine, avoid runtime data from dumped
          else
          {
            // should be a no-op!
            // \todo we could use dumped data instead if it turns out
            // there are relevant changes, but most seem to be
            // containers or callbacks. the callbacks might be the
            // relevant part and can be identified by pointing into
            // .data or .text.
            file_output.write<std::uint64_t>
              (foffs_obfuscated, file_obfuscated.read<std::uint64_t> (foffs_obfuscated));
          }
        }
      }
    }

    void copy_scy_and_imports_from_dumped() const
    {
      RawFile const file_dumped (dumped, "rb");
      PEFile const pef_dumped (dumped);

      std::size_t insert_pos (-1);
      {
        PEFile pef_output (output, true);

        pef_output.peh.setIddImportSize (pef_dumped.peh.getIddImportSize());
        pef_output.peh.setIddImportRva (pef_dumped.peh.getIddImportRva());

        pef_output.peh.setIddIatSize (pef_dumped.peh.getIddIatSize());
        pef_output.peh.setIddIatRva (pef_dumped.peh.getIddIatRva());

        auto const output_SCY_index (pef_output.peh.calcNumberOfSections());
        pef_output.peh.addSection (".SCY", pef_dumped.peh.getSizeOfRawData (pef_dumped.SCY_index));
        pef_output.peh.setCharacteristics
          (output_SCY_index, pef_dumped.peh.getCharacteristics (pef_dumped.SCY_index));

        pef_output.peh.makeValid (pef_output.pef.mzHeader().getAddressOfPeHeader());
        pef_output.peh.write (output, pef_output.pef.mzHeader().getAddressOfPeHeader());

        insert_pos = pef_output.peh.getPointerToRawData (output_SCY_index);
      }

      RawFile file_output (output, "r+b");

      file_output.insert
        ( insert_pos
        , file_dumped.read ( pef_dumped.peh.getPointerToRawData (pef_dumped.SCY_index)
                           , pef_dumped.peh.getSizeOfRawData (pef_dumped.SCY_index)
                           )
        );
    }

    void remove_broken_load_config_content_import() const
    {
      RawFile const file_obfuscated (obfuscated, "rb");
      PEFile const pef_obfuscated (obfuscated);
      RawFile const file_dumped (dumped, "rb");
      PEFile const pef_dumped (dumped);
      RawFile file_output (output, "r+b");
      PEFile const pef_output (output);

      auto const load_config_rva (pef_output.peh.getIddLoadConfigRva());
      if (!load_config_rva) throw std::logic_error ("no load config?!");

      auto const lc_cfp
        (file_output.read<std::uint64_t> (pef_output.peh.rvaToOffset (load_config_rva + 0x70)));
      auto const lc_dfp
        (file_output.read<std::uint64_t> (pef_output.peh.rvaToOffset (load_config_rva + 0x78)));

      auto const i (pef_output.imports.getNumberOfFiles (PeLib::OLDDIR) - 1);

      auto const start_rva (pef_output.imports.getFirstThunk (i, PeLib::OLDDIR));

      if (pef_output.rdata_index != pef_output.peh.getSectionWithRva (start_rva)) throw std::logic_error ("output imports are not in .rdata!?");

      auto const foffs_output (pef_output.peh.rvaToOffset (start_rva));

      if ( (foffs_output + 0) != pef_output.peh.vaToOffset (lc_cfp)
        || (foffs_output + 8) != pef_output.peh.vaToOffset (lc_dfp)
        )
      {
        throw std::logic_error ("no broken load_config content import?!");
      }

      // pef_output.imports.removeFile() sounds great, but doesn't
      // actually do what we want: it only removes functions added
      // after opening, NOT existing ones. instead, null out that
      // import manually, hoping it is the last...

      auto const impdir_rva (pef_output.peh.getIddImportRva());
      file_output.write<PeLib::PELIB_IMAGE_IMPORT_DESCRIPTOR>
        ( pef_output.peh.rvaToOffset (impdir_rva + PeLib::PELIB_IMAGE_IMPORT_DESCRIPTOR::size() * i)
        , {}
        );
    }

    void restore_rdata_import_data() const
    {
      PEFile const pef_obfuscated (obfuscated);
      RawFile const file_dumped (dumped, "rb");
      PEFile const pef_dumped (dumped);
      RawFile file_output (output, "r+b");
      PEFile const pef_output (output);

      auto const obfuscated_ib (pef_obfuscated.peh.getImageBase());
      auto const dumped_ib (pef_dumped.peh.getImageBase());
      auto const reloc_dist (dumped_ib - obfuscated_ib);

      for (std::size_t i (0); i < pef_output.imports.getNumberOfFiles (PeLib::OLDDIR); ++i)
      {
        auto const start_rva (pef_output.imports.getFirstThunk (i, PeLib::OLDDIR));

        if (pef_output.rdata_index != pef_output.peh.getSectionWithRva (start_rva)) throw std::logic_error ("output imports are not in .rdata!?");

        auto const foffs_dumped (pef_dumped.peh.rvaToOffset (start_rva));
        auto const foffs_output (pef_output.peh.rvaToOffset (start_rva));

        if (foffs_dumped != foffs_output) throw std::logic_error ("foffs diff?!");

        for (auto iter (foffs_output); true; iter += sizeof (std::uint64_t))
        {
          auto const value (file_dumped.read<std::uint64_t> (iter));
          if (!value) break;
          if (file_output.read<std::uint64_t> (iter)) throw std::logic_error ("expected .rdata to be null for imports!");
          file_output.write<std::uint64_t> (iter, value - reloc_dist);
        }
      }
    }

  } m {argv[1], argv[2], argv[3]};

  m.prepare_output_from_obfuscated();
  m.decrypt_text_segment();
  m.fix_relocations();
  m.copy_scy_and_imports_from_dumped();
  m.remove_broken_load_config_content_import();
  m.restore_rdata_import_data();

  // - todo: recalc checksum
  // - todo: verify that remaining segments changes are irrelevant

  // tls dir: has two new entries?!
  // - todo: is tls dir relevant?

  return 0;
}
catch (std::exception const& ex)
{
  std::cerr << typeid (ex).name() << ": " << ex.what() << "\n";
  return 1;
}
