use cf::solver::TurnstileSolver;
use cf::{DEMO_HREF, DEMO_SITE_KEY};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let solver = Arc::new(TurnstileSolver::new().await);

    let t = Instant::now();
    let mut task = solver
        .create_task(DEMO_SITE_KEY, DEMO_HREF, None, None)
        .await
        .unwrap();

    let result = task.solve().await;

    if let Ok(result) = result {
        println!("{:?}", result);
    } else {
        println!("err: {:#}", result.unwrap_err());
    }

    println!("Took {:?}", t.elapsed());
}
