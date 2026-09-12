// SPDX-License-Identifier: Apache-2.0
fn main() {
    sp1_build::build_program_with_args(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../guest"),
        sp1_build::BuildArgs {
            locked: true,
            ..Default::default()
        },
    );
}
