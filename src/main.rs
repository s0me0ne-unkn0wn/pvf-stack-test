use anyhow::{anyhow, Result};
use clap::Parser;
use log::trace;
// use wasm_smith;

use rand::prelude::*;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::Xoshiro256PlusPlus;
use rayon::prelude::*;
// use arbitrary::{ Arbitrary, Unstructured };
use iced_x86::{Decoder, DecoderOptions, Mnemonic, Register};
use parity_wasm::elements;
use std::cmp;
use std::fs::File;
use std::io::Write;
use target_lexicon::Triple;
use wasm_instrument::compute_stack_cost;

use xmas_elf::{
    sections::{SectionData, ShType},
    symbol_table::{Entry, Type},
    ElfFile,
};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Reproduce a case for single seed, output out.<seed>.{wasm|cwasm}
    #[clap(short, long, value_parser, conflicts_with = "wasm")]
    seed: Option<u64>,

    /// Batch size
    #[clap(
        short,
        long,
        value_parser,
        default_value_t = 100,
        conflicts_with = "seed,wasm"
    )]
    batch_size: u64,

    /// Number of batches
    #[clap(
        short,
        long,
        value_parser,
        default_value_t = 160,
        conflicts_with = "seed,wasm"
    )]
    num_batches: u64,

    /// Save every .wasm and .cwasm (slow)
    #[clap(
        short = 'v',
        long,
        value_parser,
        default_value_t = false,
        conflicts_with = "seed,wasm"
    )]
    save: bool,

    /// Run in a single thread
    #[clap(
        short = 't',
        long,
        value_parser,
        default_value_t = false,
        conflicts_with = "wasm"
    )]
    single_thread: bool,

    /// Run on an externally provided .wasm module
    #[clap(short = 'w', long, value_parser)]
    wasm: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    let target = Triple::host().to_string();
    let mut config = wasmtime::Config::new();
    config.target(&target)?;

    if let Some(wasm) = cli.wasm {
        let module = elements::deserialize_file(&wasm)?;
        let engine = wasmtime::Engine::new(&config)?;
        let res = process_module(&engine, &module, cli.save, &wasm)?;
        res.into_iter().for_each(|s| println!("{}", s));
    } else if let Some(seed) = cli.seed {
        process_batch(&config, seed, seed + 1, true)?
            .into_iter()
            .for_each(|s| println!("{}", s));
    } else if cli.single_thread {
        process_batch(&config, 0, cli.num_batches * cli.batch_size, cli.save)?
            .into_iter()
            .for_each(|s| println!("{}", s));
    } else {
        let stdout = std::io::stdout();

        (0..cli.num_batches)
            .into_par_iter()
            .flat_map(|i| {
                process_batch(
                    &config,
                    i * cli.batch_size,
                    i * (cli.batch_size + 1),
                    cli.save,
                )
                .unwrap()
            })
            .for_each(|s| {
                let _ = writeln!(&stdout, "{}", s);
            });
    }

    Ok(())
}

fn process_module(
    engine: &wasmtime::Engine,
    module: &elements::Module,
    save: bool,
    name: impl std::fmt::Display,
) -> Result<Vec<String>> {
    let mut res = Vec::<String>::new();

    if save {
        File::create(format!("out.{}.wasm", name))?.write_all(&module.clone().into_bytes()?)?;
    }

    let deffunc_idx = module.import_count(elements::ImportCountType::Function);
    let num_func = module.functions_space();
    let bytes: Vec<u8> = module.clone().into_bytes()?;
    let bin = engine.precompile_module(&bytes)?;

    if save {
        File::create(format!("out.{}.cwasm", name))?.write_all(&bin)?;
    }

    let elf = ElfFile::new(&bin).unwrap();
    let symtab = elf
        .section_iter()
        .find(|sec| sec.get_type() == Ok(ShType::SymTab))
        .expect("ELF symbol table not found");
    let text_offset = elf
        .section_iter()
        .find(|sec| sec.get_name(&elf) == Ok(".text"))
        .expect("ELF .text section not found")
        .offset();

    let func_section = module.function_section().unwrap();
    let type_section = module.type_section().unwrap();

    if let SectionData::SymbolTable64(entries) = symtab.get_data(&elf).unwrap() {
        let mut eiter = entries
            .iter()
            .filter(|e| e.get_type() == Ok(Type::Func))
            .map(|e| (e.value(), e.size(), e.get_name(&elf).unwrap()));

        for i in deffunc_idx..num_func {
            trace!("======== Processing {}, function {} ========", name, i);
            let sz = eiter.next().unwrap();
            let cost = compute_stack_cost(i as u32, module).unwrap();

            let func_sig_idx = func_section
                .entries()
                .get(i - deffunc_idx)
                .unwrap()
                .type_ref();

            let elements::Type::Function(func_signature) =
                type_section.types().get(func_sig_idx as usize).unwrap();

            let body = module
                .code_section()
                .ok_or_else(|| anyhow!("No code section"))?
                .bodies()
                .get(i - deffunc_idx)
                .ok_or_else(|| anyhow!("Function body for the index not found"))?;

            let mut decoder = Decoder::new(
                64,
                &bin[(text_offset + sz.0) as usize..(text_offset + sz.0 + sz.1) as usize],
                DecoderOptions::NONE,
            );
            let mut frame_size = 0i64;
            let mut max_frame_size = 0i64;
            let mut prev_insn: Option<Mnemonic> = None;

            for insn in decoder.iter() {
                frame_size += match insn.mnemonic() {
                    Mnemonic::Sub if insn.op_register(0) == Register::RSP => {
                        insn.immediate(1) as i64
                    }

                    // RSP subtraction always resides in either function preamble or
                    // call preamble, but a lot of postambles may be generated before every RET
                    // and every of them adds to RSP. Better heuristic is needed to catch all the
                    // postambles and treat them as invariant cases. For now, I just stick to
                    // only counting additions residing in a call postamble. That leads to possible
                    // frame size overestimation, but not to underestimations, which is the lesser evil.
                    Mnemonic::Add
                        if insn.op_register(0) == Register::RSP
                            && prev_insn == Some(Mnemonic::Call) =>
                    {
                        -(insn.immediate(1) as i64)
                    }

                    Mnemonic::Call => 8,
                    _ => 0,
                };

                max_frame_size = cmp::max(max_frame_size, frame_size);

                frame_size -= match insn.mnemonic() {
                    Mnemonic::Call => 8,
                    _ => 0,
                };

                prev_insn = Some(insn.mnemonic());
            }

            res.push(format!(
                "name {:6} idx {:2} cost {:4} frame {:4} rate {:05.2} arg {:3} res {:2} local {:3} name {:>20}",
                name,
                i,
                cost,
                max_frame_size,
                max_frame_size as f32 / cost as f32,
                func_signature.params().len(),
                func_signature.results().len(),
                body.locals().iter().map(|l| l.count()).sum::<u32>(),
                sz.2
            ));
        }
    } else {
        panic!("Symbol table does not contain 64-bit symbols");
    }

    Ok(res)
}

fn process_batch(config: &wasmtime::Config, from: u64, to: u64, save: bool) -> Result<Vec<String>> {
    let engine = wasmtime::Engine::new(config)?;
    let mut res = Vec::<String>::new();

    for seed in from..to {
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);
        let len: usize = rng.gen_range(256..65536);
        let data = (0..len).map(|_| rng.gen()).collect::<Vec<u8>>();

        let module = binaryen::tools::translate_to_fuzz_mvp(&data);
        let wasm = module.write();

        let module = elements::Module::from_bytes(wasm)?;
        res.extend(process_module(
            &engine,
            &module,
            save,
            format!("out.{}", seed),
        )?);
    }

    Ok(res)
}
