#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "linenoise.h"

#include "debugger.hpp"
#include "registers.hpp"

using namespace dbgtarget;

class ptrace_expr_context : public dwarf::expr_context {
public:
    ptrace_expr_context (pid_t pid, uint64_t load_address) : 
       m_pid{pid}, m_load_address(load_address) {}

    dwarf::taddr reg (unsigned regnum) override {
        return get_reg_value_by_dwarf(m_pid, regnum);
    }

    dwarf::taddr pc() override {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
        return regs.rip - m_load_address;
    }

    dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override {
        //TODO take into account size
        return ptrace(PTRACE_PEEKDATA, m_pid, address + m_load_address, nullptr);
    }

private:
    pid_t m_pid;
    uint64_t m_load_address;
};

template class std::initializer_list<dwarf::taddr>;
void dbg::get_vars() {

    using namespace dwarf;

    auto func_entry = get_die_by_ip(get_offset_ip());
    for (auto& entry : func_entry) {

        if (entry.tag == DW_TAG::variable) {

            auto curr_loc = entry[DW_AT::location];
            if (curr_loc.get_type() == value::type::exprloc) {

                ptrace_expr_context loc_context {m_pid, m_load_address};

                auto exprloc = curr_loc.as_exprloc().evaluate(&loc_context);
                switch (exprloc.location_type) {

					case expr_result::type::address:
						printf("%s 0x%lx = 0x%lx\n", at_name(entry).c_str(), exprloc.value, read_mem(exprloc.value));
						break;
					case expr_result::type::reg:
						printf("%s register 0x%lx = 0x%lx\n", at_name(entry).c_str(), exprloc.value, get_reg_value_by_dwarf(m_pid, exprloc.value));
						break;
					default:
						printf("Unable to find variables location\n");
				}
            }
        }
    }
}

void dbg::print_callstack() {

    auto print_frame = [fc = 0] (auto&& entry) mutable
    {
    	printf("frame %d 0x%lx %s\n", fc++, dwarf::at_low_pc(entry), dwarf::at_name(entry).c_str());
    };

    auto curr_func = get_die_by_ip(offset_load_address(get_pc()));
    print_frame(curr_func);

    auto fp = get_register_value(m_pid, reg::rbp);
    auto rtaddr = read_mem(fp + 8);

    while (dwarf::at_name(curr_func) != "main") {

        curr_func = get_die_by_ip(offset_load_address(rtaddr));
        print_frame(curr_func);
        fp = read_mem(fp);
        rtaddr = read_mem(fp + 8);
    }
}

symbol_type to_symbol_type(elf::stt sym) {
    switch (sym) {
    case elf::stt::notype: return symbol_type::notype;
    case elf::stt::object: return symbol_type::object;
    case elf::stt::func: return symbol_type::func;
    case elf::stt::section: return symbol_type::section;
    case elf::stt::file: return symbol_type::file;
    default: return symbol_type::notype;
    }
};

std::vector<symbol> dbg::lookup_symbol(const std::string& name) {
   std::vector<symbol> syms;

   for (auto& sec : m_elf.sections()) {
      if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
         continue;

      for (auto sym : sec.as_symtab()) {
         if (sym.get_name() == name) {
            auto& d = sym.get_data();
            syms.push_back(symbol{ to_symbol_type(d.type()), sym.get_name(), d.value });
         }
      }
   }

   return syms;
}

void dbg::initialise_load_address() {
   //If this is a dynamic library (e.g. PIE)
   if (m_elf.get_hdr().type == elf::et::dyn) {
      //The load address is found in /proc/<pid>/maps
      std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");

      //Read the first address from the file
      std::string addr;
      std::getline(map, addr, '-');

      m_load_address = std::stol(addr, 0, 16);
   }
}

uint64_t dbg::offset_load_address(uint64_t addr) {
   return addr - m_load_address;
}

uint64_t dbg::offset_dwarf_address(uint64_t addr) {
   return addr + m_load_address;
}

void dbg::remove_breakpoint(std::intptr_t addr) {
    if (m_breakpoints.at(addr).is_enabled()) {
        m_breakpoints.at(addr).disable();
    }
    m_breakpoints.erase(addr);
}

void dbg::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_mem(frame_pointer+8);

    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void dbg::step_in() {
   auto line = get_line_entry_from_pc(get_offset_ip())->line;

   while (get_line_entry_from_pc(get_offset_ip())->line == line) {
      single_step_instruction_with_breakpoint_check();
   }

   auto line_entry = get_line_entry_from_pc(get_offset_ip());
   print_source(line_entry->file->path, line_entry->line);
}

void dbg::step_over() {
    auto func = get_die_by_ip(get_offset_ip());
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    auto line = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(get_offset_ip());

    std::vector<std::intptr_t> to_delete{};

    while (line->address < func_end) {
        auto load_address = offset_dwarf_address(line->address);
        if (line->address != start_line->address && !m_breakpoints.count(load_address)) {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_mem(frame_pointer+8);
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for (auto addr : to_delete) {
        remove_breakpoint(addr);
    }
}

void dbg::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void dbg::single_step_instruction_with_breakpoint_check() {
    //first, check to see if we need to disable and enable a breakpoint
    if (m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    }
    else {
        single_step_instruction();
    }
}

uint64_t dbg::read_mem(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void dbg::write_mem(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t dbg::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

uint64_t dbg::get_offset_ip() {
   return offset_load_address(get_pc());
}

void dbg::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

dwarf::die dbg::get_die_by_ip(uint64_t ip) {

    for (auto &c_unit : m_dwarf.compilation_units()) {

        if (die_pc_range(c_unit.root()).contains(ip)) {

            for (auto& entry : c_unit.root()) {

                if (entry.tag == dwarf::DW_TAG::subprogram) {

                    if (die_pc_range(entry).contains(ip)) {

                        return entry;
                    }
                }
            }
        }
    }
}

dwarf::line_table::iterator dbg::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }

    throw std::out_of_range{"Cannot find line entry"};
}

void dbg::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};

    //Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    //Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    //Output cursor if we're at the current line
    std::cout << (current_line==line ? "> " : "  ");

    //Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            //Output cursor if we're at the current line
            std::cout << (current_line==line ? "> " : "  ");
        }
    }

    //Write newline and make sure that the stream is flushed properly
    std::cout << std::endl;
}

siginfo_t dbg::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void dbg::step_over_breakpoint() {

    if (m_breakpoints.count(get_pc())) {
    	printf("pc=0x%lx\n", get_pc() - m_load_address);
        auto& bp = m_breakpoints[get_pc()];
        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
        printf("pc=0x%lx\n", get_pc() - m_load_address);
    }
}

void dbg::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void dbg::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
        //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc()-1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto offset_pc = offset_load_address(get_pc()); //rember to offset the pc for querying DWARF
        auto line_entry = get_line_entry_from_pc(offset_pc);
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    //this will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void dbg::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void dbg::dump_registers() {
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << std::endl;
    }
}

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void dbg::handle_command(const std::string& line) {

    auto args = split(line,' ');
    auto command = args[0];

    if (is_prefix(command, "ce")) {

        continue_execution();
    }
    else if(is_prefix(command, "bs")) {

        if (args[1][0] == '0' && args[1][1] == 'x') {

            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        }
        else if (args[1].find(':') != std::string::npos) {

            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else {

            set_breakpoint_at_function(args[1]);
        }
    }
    else if(is_prefix(command, "s")) {

        step_in();
    }
    else if(is_prefix(command, "n")) {

        step_over();
    }
    else if(is_prefix(command, "f")) {

        step_out();
    }
    else if (is_prefix(command, "reg")) {

        if (is_prefix(args[1], "d")) {

            dump_registers();
        }
        else if (is_prefix(args[1], "r")) {

            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "w")) {

            std::string val {args[3], 2}; //assume 0xVAL
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "mem")) {

        std::string addr {args[2], 2}; //assume 0xADDRESS

        if (is_prefix(args[1], "r")) {
            std::cout << std::hex << read_mem(std::stol(addr, 0, 16)) << std::endl;
        }
        if (is_prefix(args[1], "w")) {
            std::string val {args[3], 2}; //assume 0xVAL
            write_mem(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else if(is_prefix(command, "vg")) {

        get_vars();
    }
    else if(is_prefix(command, "bt")) {

        print_callstack();
    }
    else if(is_prefix(command, "sym")) {

        auto syms = lookup_symbol(args[1]);
        for (auto&& s : syms) {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
        }
    }
    else if(is_prefix(command, "si")) {

        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    }
    else {

        std::cerr << "Unknown command\n";
    }
}

bool is_suffix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
}

void dbg::set_breakpoint_at_function(const std::string& name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry; //skip prologue
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

void dbg::set_breakpoint_at_source_line(const std::string& file, unsigned line) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        if (is_suffix(file, at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();

            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

void dbg::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void dbg::run() {
    wait_for_signal();
    initialise_load_address();

    char* line = nullptr;
    while((line = linenoise("dbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void execute_debugee (const std::string& prog_name) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //child
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);
    }
    else if (pid >= 1)  {
        //parent
        std::cout << "Started debugging process " << pid << '\n';
        dbg dbg{prog, pid};
        dbg.run();
    }
}
