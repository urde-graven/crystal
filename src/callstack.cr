{% skip_file if flag?(:win32) %}

require "c/dlfcn"
require "c/stdio"
require "c/string"
require "callstack/lib_unwind"

{% if flag?(:darwin) %}
  require "debug/mach_o"
  require "debug/dwarf"

  lib LibC
    fun _dyld_image_count : UInt32
    fun _dyld_get_image_name(image_index : UInt32) : Char*
    fun _dyld_get_image_vmaddr_slide(image_index : UInt32) : Long
  end
{% elsif flag?(:freebsd) || flag?(:linux) || flag?(:openbsd) %}
  require "debug/elf"
  require "debug/dwarf"
{% end %}

def caller
  CallStack.new.printable_backtrace
end

# :nodoc:
struct CallStack
  # Compute current directory at the beginning so filenames
  # are always shown relative to the *starting* working directory.
  CURRENT_DIR = begin
    dir = Process::INITIAL_PWD
    dir += File::SEPARATOR unless dir.ends_with?(File::SEPARATOR)
    dir
  end

  # _Unwind_Exception class (UInt64) generated from name of main "library" ("Crystal")
  UNWIND_EXCEPTION_CLASS = 7165923497316606834_u64 # "Cr}90.cr"

  @@skip = [] of String

  def self.skip(filename)
    @@skip << filename
  end

  skip(__FILE__)

  @callstack : Array(Void*)
  @backtrace : Array(String)?

  def initialize
    @callstack = CallStack.unwind
  end

  def printable_backtrace
    @backtrace ||= decode_backtrace
  end

  {% if flag?(:gnu) && flag?(:i686) %}
    # This is only used for the workaround described in `CallStack.unwind`
    @@makecontext_range : Range(Void*, Void*)?

    def self.makecontext_range
      @@makecontext_range ||= begin
        makecontext_start = makecontext_end = LibC.dlsym(LibC::RTLD_DEFAULT, "makecontext")

        while true
          ret = LibC.dladdr(makecontext_end, out info)
          break if ret == 0 || info.dli_sname.null?
          break unless LibC.strcmp(info.dli_sname, "makecontext") == 0
          makecontext_end += 1
        end

        (makecontext_start...makecontext_end)
      end
    end
  {% end %}

  protected def self.unwind
    callstack = [] of Void*
    backtrace_fn = ->(context : LibUnwind::Context, data : Void*) do
      bt = data.as(typeof(callstack))

      ip = {% if flag?(:arm) %}
             Pointer(Void).new(__crystal_unwind_get_ip(context))
           {% else %}
             Pointer(Void).new(LibUnwind.get_ip(context))
           {% end %}
      bt << ip

      {% if flag?(:gnu) && flag?(:i686) %}
        # This is a workaround for glibc bug: https://sourceware.org/bugzilla/show_bug.cgi?id=18635
        # The unwind info is corrupted when `makecontext` is used.
        # Stop the backtrace here. There is nothing interest beyond this point anyway.
        if CallStack.makecontext_range.includes?(ip)
          return LibUnwind::ReasonCode::END_OF_STACK
        end
      {% end %}

      LibUnwind::ReasonCode::NO_REASON
    end

    LibUnwind.backtrace(backtrace_fn, callstack.as(Void*))
    callstack
  end

  struct RepeatedFrame
    getter ip : Void*, count : Int32

    def initialize(@ip : Void*)
      @count = 0
    end

    def incr
      @count += 1
    end
  end

  def self.print_backtrace
    backtrace_fn = ->(context : LibUnwind::Context, data : Void*) do
      last_frame = data.as(RepeatedFrame*)

      ip = {% if flag?(:arm) %}
             Pointer(Void).new(__crystal_unwind_get_ip(context))
           {% else %}
             Pointer(Void).new(LibUnwind.get_ip(context))
           {% end %}

      if last_frame.value.ip == ip
        last_frame.value.incr
      else
        print_frame(last_frame.value) unless last_frame.value.ip.address == 0
        last_frame.value = RepeatedFrame.new ip
      end
      LibUnwind::ReasonCode::NO_REASON
    end

    rf = RepeatedFrame.new(Pointer(Void).null)
    LibUnwind.backtrace(backtrace_fn, pointerof(rf).as(Void*))
    print_frame(rf)
  end

  private def self.print_frame(repeated_frame)
    frame = decode_frame(repeated_frame.ip)
    if frame
      offset, sname = frame
      if repeated_frame.count == 0
        LibC.dprintf 2, "[0x%lx] %s +%ld\n", repeated_frame.ip, sname, offset
      else
        LibC.dprintf 2, "[0x%lx] %s +%ld (%ld times)\n", repeated_frame.ip, sname, offset, repeated_frame.count + 1
      end
    else
      if repeated_frame.count == 0
        LibC.dprintf 2, "[0x%lx] ???\n", repeated_frame.ip
      else
        LibC.dprintf 2, "[0x%lx] ??? (%ld times)\n", repeated_frame.ip, repeated_frame.count + 1
      end
    end
  end

  private def decode_backtrace
    show_full_info = ENV["CRYSTAL_CALLSTACK_FULL_INFO"]? == "1"

    @callstack.compact_map do |ip|
      fname_ptr, pc = CallStack.decode_address(ip)

      file, line, column = CallStack.decode_line_number(fname_ptr, pc)

      if file && file != "??"
        next if @@skip.includes?(file)

        # Turn to relative to the current dir, if possible
        file = file.lchop(CURRENT_DIR)

        file_line_column = "#{file}:#{line}:#{column}"
      end

      if name = CallStack.decode_function_name(fname_ptr, pc)
        function = name
      elsif frame = CallStack.decode_frame(ip)
        _, sname = frame
        function = String.new(sname)

        # We ignore these because they are part of `raise`'s internals,
        # and we can't rely on a correct filename being available
        # (for example if on Mac and without running `dsymutil`)
        #
        # We also ignore `main` because it's always at the same place
        # and adds no info.
        if function.starts_with?("*raise<") ||
           function.starts_with?("*CallStack::") ||
           function.starts_with?("*CallStack#")
          next
        end

        # Crystal methods (their mangled name) start with `*`, so
        # we remove that to have less clutter in the output.
        function = function.lchop('*')
      else
        function = "???"
      end

      if file_line_column
        if show_full_info && (frame = CallStack.decode_frame(ip))
          _, sname = frame
          line = "#{file_line_column} in '#{String.new(sname)}'"
        else
          line = "#{file_line_column} in '#{function}'"
        end
      else
        line = function
      end

      if show_full_info
        line = "#{line} at 0x#{ip.address.to_s(16)}"
      end

      line
    end
  end

  {% if flag?(:darwin) || flag?(:freebsd) || flag?(:linux) || flag?(:openbsd) %}
    class ElfInfo
      property fname : String
      property base_address : UInt64|UInt32|Nil
      property dwarf_line_numbers : Debug::DWARF::LineNumbers?
      property dwarf_function_names : Array(Tuple(LibC::SizeT, LibC::SizeT, String))?
      def initialize(@fname)
      end
    end
    protected class_getter(elfs) { {} of UInt8* => ElfInfo }

    protected def self.elf(fname_ptr)
      elfs[fname_ptr] ||= begin
        elf_info = ElfInfo.new(fname_ptr.null? ? "" : String.new(fname_ptr))
        read_dwarf_sections(elf_info)
        elf_info
      end
    end

    protected def self.decode_line_number(fname_ptr, pc)
      if ln = elf(fname_ptr).dwarf_line_numbers
        if row = ln.find(pc)
          path = "#{row.directory}/#{row.file}"
          return {path, row.line, row.column}
        end
      end
      {"??", 0, 0}
    end

    protected def self.decode_function_name(fname_ptr, pc)
      if fn = elf(fname_ptr).dwarf_function_names
        fn.each do |(low_pc, high_pc, function_name)|
          return function_name if low_pc <= pc <= high_pc
        end
      end
    end

    protected def self.parse_function_names_from_dwarf(info, strings)
      info.each do |code, abbrev, attributes|
        next unless abbrev && abbrev.tag.subprogram?
        name = low_pc = high_pc = nil

        attributes.each do |(at, form, value)|
          case at
          when Debug::DWARF::AT::DW_AT_name
            value = strings.try(&.decode(value.as(UInt32 | UInt64))) if form.strp?
            name = value.as(String)
          when Debug::DWARF::AT::DW_AT_low_pc
            low_pc = value.as(LibC::SizeT)
          when Debug::DWARF::AT::DW_AT_high_pc
            if form.addr?
              high_pc = value.as(LibC::SizeT)
            elsif value.responds_to?(:to_i)
              high_pc = low_pc.as(LibC::SizeT) + value.to_i
            end
          end
        end

        if low_pc && high_pc && name
          yield low_pc, high_pc, name
        end
      end
    end

    {% if flag?(:darwin) %}
      @@image_slide : LibC::Long?

      protected def self.read_dwarf_sections(elf_info)
        locate_dsym_bundle do |mach_o|
          mach_o.read_section?("__debug_line") do |sh, io|
            elf_info.dwarf_line_numbers = Debug::DWARF::LineNumbers.new(io, sh.size)
          end

          strings = mach_o.read_section?("__debug_str") do |sh, io|
            Debug::DWARF::Strings.new(io, sh.offset, sh.size)
          end

          mach_o.read_section?("__debug_info") do |sh, io|
            names = [] of {LibC::SizeT, LibC::SizeT, String}

            while (offset = io.pos - sh.offset) < sh.size
              info = Debug::DWARF::Info.new(io, offset)

              mach_o.read_section?("__debug_abbrev") do |sh, io|
                info.read_abbreviations(io)
              end

              parse_function_names_from_dwarf(info, strings) do |low_pc, high_pc, name|
                names << {low_pc, high_pc, name}
              end
            end

            elf_info.dwarf_function_names = names
          end
        end
      end

      # DWARF uses fixed addresses but Darwin loads exectutables at a random
      # address, so we must remove the load offset from the IP to match the
      # addresses in DWARF sections.
      #
      # See https://en.wikipedia.org/wiki/Address_space_layout_randomization
      protected def self.decode_address(ip)
        {Pointer(UInt8).null, ip.address - image_slide}
      end

      # Searches the companion dSYM bundle with the DWARF sections for the
      # current program as generated by `dsymutil`. It may be a `foo.dwarf` file
      # or within a `foo.dSYM` bundle for a program named `foo`.
      #
      # See <http://wiki.dwarfstd.org/index.php?title=Apple%27s_%22Lazy%22_DWARF_Scheme> for details.
      private def self.locate_dsym_bundle
        program = Process.executable_path
        return unless program

        files = {
          "#{program}.dSYM/Contents/Resources/DWARF/#{File.basename(program)}",
          "#{program}.dwarf"
        }

        files.each do |dwarf|
          next unless File.exists?(dwarf)

          Debug::MachO.open(program) do |mach_o|
            Debug::MachO.open(dwarf) do |dsym|
              if dsym.uuid == mach_o.uuid
                return yield dsym
              end
            end
          end
        end

        nil
      end

      # The address offset at which the program was loaded at.
      private def self.image_slide
        @@image_slide ||= search_image_slide
      end

      private def self.search_image_slide
        buffer = GC.malloc_atomic(LibC::PATH_MAX).as(UInt8*)
        size = LibC::PATH_MAX.to_u32

        if LibC._NSGetExecutablePath(buffer, pointerof(size)) == -1
          buffer = GC.malloc_atomic(size).as(UInt8*)
          if LibC._NSGetExecutablePath(buffer, pointerof(size)) == -1
            return LibC::Long.new(0)
          end
        end

        program = String.new(buffer)

        LibC._dyld_image_count.times do |i|
          if program == String.new(LibC._dyld_get_image_name(i))
            return LibC._dyld_get_image_vmaddr_slide(i)
          end
        end

        LibC::Long.new(0)
      end
    {% else %}

      protected def self.read_dwarf_sections(elf_info)
        return if elf_info.fname.empty?
        Debug::ELF.open(elf_info.fname) do |elf|
          elf.read_section?(".text") do |sh, _|
            elf_info.base_address = sh.addr - sh.offset
          end

          elf.read_section?(".debug_line") do |sh, io|
            elf_info.dwarf_line_numbers = Debug::DWARF::LineNumbers.new(io, sh.size)
          end

          strings = elf.read_section?(".debug_str") do |sh, io|
            Debug::DWARF::Strings.new(io, sh.offset, sh.size)
          end

          elf.read_section?(".debug_info") do |sh, io|
            names = [] of {LibC::SizeT, LibC::SizeT, String}

            while (offset = io.pos - sh.offset) < sh.size
              info = Debug::DWARF::Info.new(io, offset)

              elf.read_section?(".debug_abbrev") do |sh, io|
                info.read_abbreviations(io)
              end

              parse_function_names_from_dwarf(info, strings) do |name, low_pc, high_pc|
                names << {name, low_pc, high_pc}
              end
            end

            elf_info.dwarf_function_names = names
          end
        end
      rescue e : Errno
      end

      # DWARF uses fixed addresses but some platforms (e.g., OpenBSD or Linux
      # with the [PaX patch](https://en.wikipedia.org/wiki/PaX)) load
      # executables at a random address, so we must remove the load offset from
      # the IP to match the addresses in DWARF sections.
      #
      # See https://en.wikipedia.org/wiki/Address_space_layout_randomization
      protected def self.decode_address(ip)
        if LibC.dladdr(ip, out info) != 0
          unless info.dli_fbase.address == elf(info.dli_fname).base_address
            ip -= info.dli_fbase.address
          end
          return {info.dli_fname, ip.address}
        end
        {Pointer(UInt8).null, ip.address}
      end
    {% end %}
  {% else %}
    protected  def self.decode_address(ip)
      {Pointer(UInt8).null, ip.address}
    end

    protected  def self.decode_line_number(fname, pc)
      {"??", 0, 0}
    end

    protected def self.decode_function_name(fname, pc)
      nil
    end
  {% end %}

  protected def self.decode_frame(ip, original_ip = ip)
    if LibC.dladdr(ip, out info) != 0
      offset = original_ip - info.dli_saddr

      if offset == 0
        return decode_frame(ip - 1, original_ip)
      end

      unless info.dli_sname.null?
        {offset, info.dli_sname}
      end
    end
  end

  def self.decode_exception_class(except_class : UInt64) : String
    buf = uninitialized UInt8[8]
    8.times do |i|
      buf[7 - i] = except_class.to_u8
      except_class = except_class >> 8
    end
    String.new(buf.to_unsafe, buf.size)
  end
end
